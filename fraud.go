package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/db/rocksdb"
	"github.com/cosmos/cosmos-sdk/store/rootmulti"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	"github.com/cosmos/cosmos-sdk/store/v2alpha1/multi"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	paramskeeper "github.com/cosmos/cosmos-sdk/x/params/keeper"
	paramstypes "github.com/cosmos/cosmos-sdk/x/params/types"
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto/merkle"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmcrypto "github.com/tendermint/tendermint/proto/tendermint/crypto"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"

	"github.com/tharsis/ethermint/app"
	"github.com/tharsis/ethermint/crypto/ethsecp256k1"
	evmenc "github.com/tharsis/ethermint/encoding"
	"github.com/tharsis/ethermint/server/config"
	"github.com/tharsis/ethermint/tests"
	ethermint "github.com/tharsis/ethermint/types"
	evmkeeper "github.com/tharsis/ethermint/x/evm/keeper"
	evmtypes "github.com/tharsis/ethermint/x/evm/types"
	feemarketkeeper "github.com/tharsis/ethermint/x/feemarket/keeper"
	feemarkettypes "github.com/tharsis/ethermint/x/feemarket/types"
)

/*
TODO:
- generate some ethereum transactions
- generate execution trace/state fraud proof
- bootstrap a kv store from fraud proof
*/
const (
	blockHeight         = 1
	chainID             = "evm"
	traceWriterFilename = "execution.trace"
)

var (
	userAddr = common.HexToAddress("0x378c50D9264C63F3F92B806d4ee56E9D86FfB3Ec")
)

func main() {
	sdkCtx, cms, err := setupSDKContext()
	if err != nil {
		log.Fatal(err)
	}
	err = setupTracer(traceWriterFilename, cms)
	if err != nil {
		log.Fatal(err)
	}

	// Setup evm keeper.
	evmKeeper := setupEVMKeeper(sdkCtx, cms)

	signer, account, err := setupSigner()
	if err != nil {
		log.Fatal(err)
	}

	// Deploy ERC20 + run some ERC20 txs.
	contractAddr, err := deployERC20(sdkCtx, evmKeeper, account, signer)
	if err != nil {
		log.Fatal(err)
	}
	err = transferERC20(sdkCtx, evmKeeper, contractAddr, account, userAddr,
		sdk.NewIntWithDecimal(1, 18).BigInt(), signer)
	if err != nil {
		log.Fatal(err)
	}

	cms.Commit()

	proof, err := getFraudProof(traceWriterFilename, cms)
	if err != nil {
		log.Fatal(err)
	}

	_, err = NewPartialKVStore(proof)
	if err != nil {
		log.Fatal(err)
	}
}

func setupSDKContext() (sdk.Context, sdk.CommitMultiStore, error) {
	// Setup db/store/context.
	dataDir, err := ioutil.TempDir("", "data")
	if err != nil {
		return sdk.Context{}, nil, err
	}
	//db, err := sdk.NewLevelDB("application", dataDir)
	db, err := rocksdb.NewDB(dataDir)
	if err != nil {
		return sdk.Context{}, nil, err
	}
	//cms := store.NewCommitMultiStore(db)
	cms := multi.NewStore(db)
	sdkCtx := sdk.NewContext(cms, tmproto.Header{Height: blockHeight, ChainID: chainID}, false, tmlog.NewNopLogger())
	return sdkCtx, cms, nil
}

func setupSigner() (keyring.Signer, common.Address, error) {
	// Setup constant account key.
	ecdsaPriv, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		return nil, common.Address{}, nil
	}
	priv := &ethsecp256k1.PrivKey{
		Key: crypto.FromECDSA(ecdsaPriv),
	}
	return tests.NewSigner(priv), common.BytesToAddress(priv.PubKey().Address().Bytes()), nil
}

func setupTracer(traceFileName string, cms sdk.CommitMultiStore) error {
	w, err := os.OpenFile(
		filepath.Clean(traceFileName),
		os.O_WRONLY|os.O_APPEND|os.O_CREATE,
		0o600,
	)
	if err != nil {
		return err
	}
	cms.SetTracer(w)
	return nil
}

func setupEVMKeeper(sdkCtx sdk.Context, cms sdk.CommitMultiStore) *evmkeeper.Keeper {
	maccPerms := map[string][]string{
		evmtypes.ModuleName:            {authtypes.Minter, authtypes.Burner},
		stakingtypes.BondedPoolName:    {authtypes.Burner, authtypes.Staking},
		stakingtypes.NotBondedPoolName: {authtypes.Burner, authtypes.Staking},
	}

	encodingConfig := evmenc.MakeConfig(app.ModuleBasics)
	appCodec := encodingConfig.Marshaler
	cdc := encodingConfig.Amino

	keys := sdk.NewKVStoreKeys(
		evmtypes.StoreKey, paramstypes.StoreKey, authtypes.StoreKey,
		banktypes.StoreKey, stakingtypes.StoreKey,
	)
	tkeys := sdk.NewTransientStoreKeys(evmtypes.TransientKey, paramstypes.TStoreKey)
	for _, key := range keys {
		cms.MountStoreWithDB(key, sdk.StoreTypeIAVL, nil)
	}
	for _, key := range tkeys {
		cms.MountStoreWithDB(key, sdk.StoreTypeTransient, nil)
	}
	cms.LoadVersion(0) // Need to load initial version.

	paramsKeeper := paramskeeper.NewKeeper(appCodec, cdc, keys[paramstypes.StoreKey], tkeys[paramstypes.TStoreKey])
	for _, moduleName := range []string{
		evmtypes.ModuleName, authtypes.ModuleName, banktypes.ModuleName,
		stakingtypes.ModuleName,
		feemarkettypes.ModuleName,
	} {
		paramsKeeper.Subspace(moduleName)
	}

	authSubspace, _ := paramsKeeper.GetSubspace(authtypes.ModuleName)
	accountKeeper := authkeeper.NewAccountKeeper(
		appCodec, keys[authtypes.StoreKey], authSubspace, ethermint.ProtoAccount, maccPerms,
	)

	bankSubspace, _ := paramsKeeper.GetSubspace(banktypes.ModuleName)
	bankKeeper := bankkeeper.NewBaseKeeper(
		appCodec, keys[banktypes.StoreKey], accountKeeper, bankSubspace, nil,
	)

	stakingSubspace, _ := paramsKeeper.GetSubspace(stakingtypes.ModuleName)
	stakingKeeper := stakingkeeper.NewKeeper(
		appCodec, keys[stakingtypes.StoreKey], accountKeeper, bankKeeper, stakingSubspace,
	)

	// NB: Feemarket is optional.
	feemarketSubspace, _ := paramsKeeper.GetSubspace(feemarkettypes.ModuleName)
	feemarketKeeper := feemarketkeeper.NewKeeper(
		appCodec, keys[feemarkettypes.StoreKey], feemarketSubspace,
	)
	params := feemarkettypes.DefaultParams()
	for _, pair := range params.ParamSetPairs() {
		feemarketSubspace.Set(sdkCtx, pair.Key, pair.Value)
	}

	evmSubspace, _ := paramsKeeper.GetSubspace(evmtypes.ModuleName)
	evmKeeper := evmkeeper.NewKeeper(
		appCodec, keys[evmtypes.StoreKey], tkeys[evmtypes.TransientKey], evmSubspace,
		accountKeeper, bankKeeper, stakingKeeper,
		feemarketKeeper,
		evmtypes.TracerJSON,
	)
	evmParams := evmtypes.DefaultParams()
	for _, pair := range evmParams.ParamSetPairs() {
		evmSubspace.Set(sdkCtx, pair.Key, pair.Value)
	}

	return evmKeeper
}

func deployERC20(
	sdkCtx sdk.Context,
	evm *evmkeeper.Keeper,
	account common.Address,
	signer keyring.Signer,
) (common.Address, error) {
	ctx := sdk.WrapSDKContext(sdkCtx)
	chainID := evm.ChainID()

	ctorArgs, err := evmtypes.ERC20Contract.ABI.Pack("", account, sdk.NewIntWithDecimal(1000, 18).BigInt())
	if err != nil {
		return common.Address{}, err
	}
	data := append(evmtypes.ERC20Contract.Bin, ctorArgs...)
	args, err := json.Marshal(&evmtypes.TransactionArgs{
		From: &account,
		Data: (*hexutil.Bytes)(&data),
	})
	if err != nil {
		return common.Address{}, err
	}

	res, err := evm.EstimateGas(ctx, &evmtypes.EthCallRequest{
		Args:   args,
		GasCap: uint64(config.DefaultGasCap),
	})
	if err != nil {
		return common.Address{}, err
	}
	nonce := evm.GetNonce(sdkCtx, account)

	erc20DeployTx := evmtypes.NewTxContract(
		chainID,
		nonce,
		nil,      // amount
		res.Gas,  // gasLimit
		nil,      // gasPrice
		nil, nil, // gasFeeCap, gasTipCap (only used when feemarket is active)
		data, // input
		nil,  // accesses
	)
	erc20DeployTx.From = account.Hex()
	err = erc20DeployTx.Sign(ethtypes.LatestSignerForChainID(evm.ChainID()), signer)
	if err != nil {
		return common.Address{}, err
	}

	txResp, err := evm.EthereumTx(ctx, erc20DeployTx)
	if err != nil {
		return common.Address{}, err
	}
	if txResp.VmError != "" {
		return common.Address{}, errors.New(txResp.VmError)
	}

	return crypto.CreateAddress(account, nonce), nil
}

func transferERC20(
	sdkCtx sdk.Context,
	evm *evmkeeper.Keeper,
	contractAddr, from, to common.Address,
	amount *big.Int,
	signer keyring.Signer,
) error {
	ctx := sdk.WrapSDKContext(sdkCtx)
	chainID := evm.ChainID()

	transferData, err := evmtypes.ERC20Contract.ABI.Pack("transfer", to, amount)
	if err != nil {
		return err
	}

	args, err := json.Marshal(&evmtypes.TransactionArgs{
		To:   &contractAddr,
		From: &from,
		Data: (*hexutil.Bytes)(&transferData),
	})
	if err != nil {
		return err
	}

	res, err := evm.EstimateGas(ctx, &evmtypes.EthCallRequest{
		Args:   args,
		GasCap: uint64(config.DefaultGasCap),
	})
	if err != nil {
		return err
	}
	nonce := evm.GetNonce(sdkCtx, from) // Assume token sender is the signer

	/*
		chainID *big.Int, nonce uint64, to *common.Address, amount *big.Int,
		gasLimit uint64, gasPrice, gasFeeCap, gasTipCap *big.Int, input []byte, accesses *ethtypes.AccessList,
	*/
	transferTx := evmtypes.NewTx(
		chainID,
		nonce,
		&contractAddr, // to
		nil,           // amount
		res.Gas,       // gasLmit
		nil,           // gasPrice
		nil, nil,      // gasFeeCap, gasTipCap (only used when feemarket is active)
		transferData, // input
		nil,          // accesses
	)
	transferTx.From = from.Hex()
	err = transferTx.Sign(ethtypes.LatestSignerForChainID(evm.ChainID()), signer)
	if err != nil {
		return err
	}

	txResp, err := evm.EthereumTx(ctx, transferTx)
	if err != nil {
		return err
	}
	if txResp.VmError != "" {
		return errors.New(txResp.VmError)
	}

	return nil
}

type Operation string

type TraceOperation struct {
	Operation Operation              `json:"operation"`
	Key       string                 `json:"key"`
	Value     string                 `json:"value"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type FraudProof struct {
	PreISR    []byte
	PostISR   []byte
	Witnesses []StateWitness
}

type StateWitness struct {
	Key   []byte
	Value []byte
	// Merkle inclusion proof of k/v pair in merkle root.
	ProofOps *tmcrypto.ProofOps
}

var (
	prt = rootmulti.DefaultProofRuntime()
	// Expected hardcoded key for testing.
	// key, _ = base64.StdEncoding.DecodeString("ZXZtL0VuYWJsZUNyZWF0ZQ==") // evm/EnableCreate
)

func getFraudProof(
	traceFileName string,
	cms sdk.CommitMultiStore,
) (FraudProof, error) {
	f, err := os.Open(traceWriterFilename)
	if err != nil {
		return FraudProof{}, err
	}
	var (
		reader = bufio.NewReader(f)
		seen   = make(map[string]struct{})
		proof  = FraudProof{
			Witnesses: make([]StateWitness, 0),
			PreISR:    cms.LastCommitID().Hash,
			PostISR:   cms.Commit().Hash,
		}
		traceOp TraceOperation
		line    []byte
	)
	for line, err = reader.ReadBytes('\n'); err == nil; line, err = reader.ReadBytes('\n') {
		if err := json.Unmarshal(line, &traceOp); err != nil {
			return FraudProof{}, err
		}

		if _, ok := seen[traceOp.Key]; ok {
			continue
		}

		key, err := base64.StdEncoding.DecodeString(traceOp.Key)
		if err != nil {
			return FraudProof{}, err
		}
		witness, err := getStateWitness(key, cms.Commit(), cms)
		if err != nil {
			return FraudProof{}, err
		}

		proof.Witnesses = append(proof.Witnesses, witness)

		seen[traceOp.Key] = struct{}{}
	}
	if err != io.EOF {
		return FraudProof{}, err
	}
	return proof, nil
}

func getStateWitness(
	key []byte,
	commit storetypes.CommitID,
	cms sdk.CommitMultiStore,
) (StateWitness, error) {
	queryable, ok := cms.(storetypes.Queryable)
	if !ok {
		return StateWitness{}, errors.New("store not queryable")
	}
	res := queryable.Query(abci.RequestQuery{
		Path:   "/evm/key",
		Data:   key,
		Height: commit.Version,
		Prove:  true,
	})
	return StateWitness{
		Key:      res.Key,
		Value:    res.Value,
		ProofOps: res.ProofOps,
	}, nil
}

type PartialMultiStore struct {
	kvStoreOverrides map[storetypes.StoreKey]storetypes.KVStore
	storetypes.CommitMultiStore
}

func (p *PartialMultiStore) GetKVStore(key storetypes.StoreKey) storetypes.KVStore {
	store, ok := p.kvStoreOverrides[key]
	if ok {
		return store
	}
	return p.CommitMultiStore.GetKVStore(key)
}

type PartialKVStore struct {
	proof FraudProof
	pozs  []merkle.ProofOperators
}

func NewPartialKVStore(proof FraudProof) (PartialKVStore, error) {
	pozs := make([]merkle.ProofOperators, 0, len(proof.Witnesses))
	for witnessIdx, witness := range proof.Witnesses {
		poz := make(merkle.ProofOperators, 0, len(witness.ProofOps.Ops))
		for opIdx, op := range witness.ProofOps.Ops {
			po, err := storetypes.CommitmentOpDecoder(op)
			if err != nil {
				return PartialKVStore{}, err
			}
			// NB:In-VM keys are encoded in non readable form. Run length encoded??
			// TODO: Convert to plaintext to see?
			// Cosmos keys are encoded in readable form with "/" separators.
			log.Println("Op ->", witnessIdx, opIdx, string(op.Key), op.Type)
			poz = append(poz, po)
		}
		pozs = append(pozs, poz)

	}
	return PartialKVStore{
		proof: proof,
		pozs:  pozs,
	}, nil
}

func (p *PartialKVStore) Get(key []byte) []byte {
	return nil
}

func (p *PartialKVStore) Has(key []byte) bool {
	return true
}

func (p *PartialKVStore) Set(key, value []byte) {
}

func (p *PartialKVStore) Delete(key []byte) {
}

func (p *PartialKVStore) Iterator(start, end []byte) storetypes.Iterator {
	panic("not implemented")
}

func (p *PartialKVStore) ReverseIterator(start, end []byte) storetypes.Iterator {
	panic("not implemented")
}
