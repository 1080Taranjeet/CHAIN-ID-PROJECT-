package main

import (
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "time"
    "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ChainIDContract defines the smart contract structure
type ChainIDContract struct {
    contractapi.Contract
}

// SessionBlock represents a session block structure
type SessionBlock struct {
    BlockIndex   int       `json:"block_index"`
    UserEmail    string    `json:"user_email"`
    SignupMethod string    `json:"signup_method"`
    DeviceID     string    `json:"device_id"`
    Action       string    `json:"action"`
    Timestamp    time.Time `json:"timestamp"`
    ExpiresAt    time.Time `json:"expires_at"`
    PreviousHash string    `json:"previous_hash"`
    CurrentHash  string    `json:"current_hash"`
    Nonce        int       `json:"nonce"`
}

// DataBlock represents a main blockchain block
type DataBlock struct {
    Index        int       `json:"index"`
    Timestamp    time.Time `json:"timestamp"`
    Data         string    `json:"data"` // JSON string of data
    PreviousHash string    `json:"previous_hash"`
    Hash         string    `json:"hash"`
}

// InitLedger initializes the ledger with a genesis block
func (c *ChainIDContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
    genesisData := map[string]string{
        "type":        "genesis",
        "timestamp":   time.Now().UTC().Format(time.RFC3339),
        "description": "Genesis block for ChainID blockchain",
    }
    genesisDataBytes, _ := json.Marshal(genesisData)
    genesisBlock := DataBlock{
        Index:        0,
        Timestamp:    time.Now().UTC(),
        Data:         string(genesisDataBytes),
        PreviousHash: "0",
    }
    genesisBlock.Hash = calculateDataBlockHash(genesisBlock)
    genesisBytes, _ := json.Marshal(genesisBlock)
    err := ctx.GetStub().PutState("block_0", genesisBytes)
    if err != nil {
        return fmt.Errorf("failed to create genesis block: %v", err)
    }
    return nil
}

// CreateSessionBlock creates a new session block with proof-of-work
func (c *ChainIDContract) CreateSessionBlock(ctx contractapi.TransactionContextInterface, blockIndex int, userEmail, signupMethod, deviceID, action string, timestamp, expiresAt time.Time, previousHash string) (*SessionBlock, error) {
    nonce := 0
    difficulty := 2 // Matches SESSION_BLOCKCHAIN_DIFFICULTY
    block := SessionBlock{
        BlockIndex:   blockIndex,
        UserEmail:    userEmail,
        SignupMethod: signupMethod,
        DeviceID:     deviceID,
        Action:       action,
        Timestamp:    timestamp,
        ExpiresAt:    expiresAt,
        PreviousHash: previousHash,
        Nonce:        nonce,
    }

    // Proof-of-work mining
    for {
        block.Nonce = nonce
        block.CurrentHash = calculateSessionBlockHash(block)
        if block.CurrentHash[:difficulty] == string(make([]byte, difficulty)) {
            break
        }
        nonce++
    }

    blockBytes, err := json.Marshal(block)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal session block: %v", err)
    }

    err = ctx.GetStub().PutState(fmt.Sprintf("session_block_%d", blockIndex), blockBytes)
    if err != nil {
        return nil, fmt.Errorf("failed to save session block: %v", err)
    }

    return &block, nil
}

// AddDataBlock adds a new block to the main blockchain
func (c *ChainIDContract) AddDataBlock(ctx contractapi.TransactionContextInterface, index int, data string, previousHash string) (*DataBlock, error) {
    block := DataBlock{
        Index:        index,
        Timestamp:    time.Now().UTC(),
        Data:         data,
        PreviousHash: previousHash,
    }
    block.Hash = calculateDataBlockHash(block)

    blockBytes, err := json.Marshal(block)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal data block: %v", err)
    }

    err = ctx.GetStub().PutState(fmt.Sprintf("block_%d", index), blockBytes)
    if err != nil {
        return nil, fmt.Errorf("failed to save data block: %v", err)
    }

    return &block, nil
}

// ValidateChain validates the session and data blockchain
func (c *ChainIDContract) ValidateChain(ctx contractapi.TransactionContextInterface) (bool, string) {
    // Validate data blocks
    for i := 0; ; i++ {
        blockBytes, err := ctx.GetStub().GetState(fmt.Sprintf("block_%d", i))
        if err != nil {
            return false, fmt.Sprintf("failed to read block_%d: %v", i, err)
        }
        if blockBytes == nil {
            break // End of chain
        }

        var block DataBlock
        if err := json.Unmarshal(blockBytes, &block); err != nil {
            return false, fmt.Sprintf("failed to unmarshal block_%d: %v", i, err)
        }

        computedHash := calculateDataBlockHash(block)
        if block.Hash != computedHash {
            return false, fmt.Sprintf("hash mismatch at block_%d", i)
        }

        if i > 0 {
            prevBlockBytes, err := ctx.GetStub().GetState(fmt.Sprintf("block_%d", i-1))
            if err != nil || prevBlockBytes == nil {
                return false, fmt.Sprintf("missing previous block_%d", i-1)
            }
            var prevBlock DataBlock
            json.Unmarshal(prevBlockBytes, &prevBlock)
            if block.PreviousHash != prevBlock.Hash {
                return false, fmt.Sprintf("broken link at block_%d", i)
            }
        } else if block.PreviousHash != "0" {
            return false, "invalid genesis block"
        }
    }

    // Validate session blocks
    for i := 0; ; i++ {
        blockBytes, err := ctx.GetStub().GetState(fmt.Sprintf("session_block_%d", i))
        if err != nil {
            return false, fmt.Sprintf("failed to read session_block_%d: %v", i, err)
        }
        if blockBytes == nil {
            break // End of chain
        }

        var block SessionBlock
        if err := json.Unmarshal(blockBytes, &block); err != nil {
            return false, fmt.Sprintf("failed to unmarshal session_block_%d: %v", i, err)
        }

        computedHash := calculateSessionBlockHash(block)
        if block.CurrentHash != computedHash {
            return false, fmt.Sprintf("hash mismatch at session_block_%d", i)
        }

        if block.CurrentHash[:2] != "00" { // Check PoW
            return false, fmt.Sprintf("invalid PoW at session_block_%d", i)
        }

        if i > 0 {
            prevBlockBytes, err := ctx.GetStub().GetState(fmt.Sprintf("session_block_%d", i-1))
            if err != nil || prevBlockBytes == nil {
                return false, fmt.Sprintf("missing previous session_block_%d", i-1)
            }
            var prevBlock SessionBlock
            json.Unmarshal(prevBlockBytes, &prevBlock)
            if block.PreviousHash != prevBlock.CurrentHash {
                return false, fmt.Sprintf("broken link at session_block_%d", i)
            }
        }
    }

    return true, ""
}

// GetSessionBlock retrieves a session block by index
func (c *ChainIDContract) GetSessionBlock(ctx contractapi.TransactionContextInterface, blockIndex int) (*SessionBlock, error) {
    blockBytes, err := ctx.GetStub().GetState(fmt.Sprintf("session_block_%d", blockIndex))
    if err != nil {
        return nil, fmt.Errorf("failed to read session_block_%d: %v", blockIndex, err)
    }
    if blockBytes == nil {
        return nil, fmt.Errorf("session_block_%d not found", blockIndex)
    }

    var block SessionBlock
    if err := json.Unmarshal(blockBytes, &block); err != nil {
        return nil, fmt.Errorf("failed to unmarshal session_block_%d: %v", blockIndex, err)
    }
    return &block, nil
}

// GetActiveSessions retrieves active sessions for a user
func (c *ChainIDContract) GetActiveSessions(ctx contractapi.TransactionContextInterface, userEmail string) ([]SessionBlock, error) {
    queryString := fmt.Sprintf(`{"selector":{"user_email":"%s","action":"login","expires_at":{"$gt":"%s"}}}`, userEmail, time.Now().UTC().Format(time.RFC3339))
    resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
    if err != nil {
        return nil, fmt.Errorf("failed to query active sessions: %v", err)
    }
    defer resultsIterator.Close()

    var sessions []SessionBlock
    for resultsIterator.HasNext() {
        queryResponse, err := resultsIterator.Next()
        if err != nil {
            return nil, fmt.Errorf("failed to iterate results: %v", err)
        }

        var block SessionBlock
        if err := json.Unmarshal(queryResponse.Value, &block); err != nil {
            return nil, fmt.Errorf("failed to unmarshal session block: %v", err)
        }

        // Check for logout
        logoutQuery := fmt.Sprintf(`{"selector":{"user_email":"%s","action":"logout","timestamp":{"$gt":"%s"}}}`, userEmail, block.Timestamp.Format(time.RFC3339))
        logoutIterator, err := ctx.GetStub().GetQueryResult(logoutQuery)
        if err != nil {
            continue
        }
        if !logoutIterator.HasNext() {
            sessions = append(sessions, block)
        }
        logoutIterator.Close()
    }

    return sessions, nil
}

// Helper functions
func calculateSessionBlockHash(block SessionBlock) string {
    blockString := fmt.Sprintf("%d%s%s%s%s%s%s%d",
        block.BlockIndex,
        block.UserEmail,
        block.SignupMethod,
        block.DeviceID,
        block.Action,
        block.Timestamp.Format(time.RFC3339),
        block.ExpiresAt.Format(time.RFC3339),
        block.PreviousHash,
        block.Nonce,
    )
    hash := sha256.Sum256([]byte(blockString))
    return fmt.Sprintf("%x", hash)
}

func calculateDataBlockHash(block DataBlock) string {
    blockString := fmt.Sprintf("%d%s%s%s",
        block.Index,
        block.Timestamp.Format(time.RFC3339),
        block.Data,
        block.PreviousHash,
    )
    hash := sha256.Sum256([]byte(blockString))
    return fmt.Sprintf("%x", hash)
}

func main() {
    chaincode, err := contractapi.NewChaincode(&ChainIDContract{})
    if err != nil {
        fmt.Printf("Error creating chaincode: %v", err)
        return
    }
    if err := chaincode.Start(); err != nil {
        fmt.Printf("Error starting chaincode: %v", err)
    }
}