#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <vector>
#include <chrono>
#include <memory>
#include <mutex>
#include <ctime>
#include <exception>
#include <stdexcept>
#include <optional>
#include <variant>
#include <future>
#include <openssl/ec.h>
#include <list>
#include <nlohmann/json.hpp>
#include <sqlite3.h> 


using json = nlohmann::json;

class TransactionException : public std::runtime_error {
public:
    explicit TransactionException(const std::string& message) : std::runtime_error(message) {}
};
class SecureTransactionException : public std::runtime_error {
public:
    explicit SecureTransactionException(const std::string& message)
        : std::runtime_error(message) {}
};

class Transaction {
public:
    enum class TransactionType { SIMPLE_TRANSFER, NFT_TRANSFER, COIN_BURN };
    enum class Status { PENDING, COMPLETED, FAILED };
enum class TransactionType { SIMPLE_TRANSFER, NFT_TRANSFER, COIN_BURN, STAKING, UNSTAKING };
struct TransactionDetail {
        std::string txnHash;
        std::string sender;
        std::string receiver;
        double value;
        std::time_t timestamp;
        std::string nonce;
        bool signedStatus = false;
        std::string signature;
    };
private:
    std::string sender;            // فرستنده
    std::string receiver;          // گیرنده
    double value;                  // مقدار تراکنش
    std::string assetId;           // شناسه دارایی (اختیاری برای NFT)
    
    std::string txnHash;           // هش تراکنش
    std::string signature;          // امضای دیجیتال برای امنیت
    bool isVerified;               // وضعیت تأیید
double transactionFee;
    
    std::time_t timestamp;
    TransactionType type;
    
    Status status;
    std::string memo;
    std::optional<std::string> signature;
    std::string nonce; // برای جلوگیری از حملات Replay
    std::mutex txnMutex;
    
    std::string computeHash() const {
        std::stringstream ss;
        ss << sender << receiver << value << assetId << timestamp << (int)type;
        std::string input = ss.str();
unsigned char hash[SHA512_DIGEST_LENGTH]; 
      
        SHA512(reinterpret_cast<unsigned char*>(hash), reinterpret_cast<const unsigned char*>(input.c_str()), input.size());

        std::stringstream hashStream;
        for (unsigned char byte : hash) {
            hashStream << std::setw(2) << std::setfill('0') << std::hex << (int)byte;
        }
        return hashStream.str();
    }
   std::string serialize() const {
       std::stringstream ss;
       ss << sender << receiver << value << transactionFee << assetId << timestamp << static_cast<int>(type);
        std::string input = ss.str();
        std::hash<std::string> hash_fn;
        size_t hash = hash_fn(input);
        return std::to_string(hash);
   }
   std::string generateNonce(size_t length) {
        const char chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::string nonce(length, ' ');
        RAND_bytes(reinterpret_cast<unsigned char*>(&nonce[0]), length);
        for (size_t i = 0; i < length; ++i) {
            nonce[i] = chars[nonce[i] % (sizeof(chars) - 1)];
        }
        return nonce;
    }
    std::string generateHash(const std::string& data) {
        unsigned char hash[SHA512_DIGEST_LENGTH];
        SHA512(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
        std::stringstream hashStream;
        for (unsigned char byte : hash) {
            hashStream << std::setw(2) << std::setfill('0') << std::hex << (int)byte;
        }
        return hashStream.str();
    }

    std::string generateHMAC(const std::string& key, const std::string& data) {
        unsigned char* hmac = HMAC(EVP_sha512(), key.data(), key.size(), reinterpret_cast<const unsigned char*>(data.data()), data.size(),nullptr, nullptr);
        return std::string(reinterpret_cast<char*>(hmac), SHA512_DIGEST_LENGTH);
    }
    Transaction(const std::string& sender, const std::string& receiver, double transactionFee = 0.01,
                const std::string& assetId, TransactionType type)
        : sender(sender), receiver(receiver), value(0.01), assetId(assetId), type(type) {
        timestamp = std::time(nullptr);
        nonce = generateNonce(16); // تولید nonce
        std::string data = sender + receiver + std::to_string(value) + assetId + std::to_string(timestamp) + nonce;
        txnHash = generateHash(data);
    }
    void signTransaction(const std::string& privateKey) {
        std::lock_guard<std::mutex> lock(txnMutex);
        RSA* rsaPrivKey = RSA_new();
        BIO* bio = BIO_new_mem_buf(privateKey.data(), -1);
        PEM_read_bio_RSAPrivateKey(bio, &rsaPrivKey, nullptr, nullptr);
        
        unsigned char hash[SHA512_DIGEST_LENGTH];
        SHA512(reinterpret_cast<const unsigned char*>(txnHash.data()), txnHash.size(), hash);
        
       std::unique_ptr<unsigned char[]> sig(new unsigned char[RSA_size(rsaPrivKey)]);
        unsigned int sigLen;

   if (RSA_sign(NID_sha512, hash, SHA512_DIGEST_LENGTH, sig.get(), &sigLen, rsaPrivKey) != 1) {
            RSA_free(rsaPrivKey);
            BIO_free(bio);
            throw SecureTransactionException("Failed to sign transaction.");
        }

        signature = std::string(reinterpret_cast<char*>(sig.get()), sigLen);
        storeTransaction();
        
        RSA_free(rsaPrivKey);
        BIO_free(bio);
    }

void verifyTransaction(const std::string& publicKey) const {
        std::lock_guard<std::mutex> lock(txnMutex);
        if (!signature) {
            throw SecureTransactionException("Transaction has not been signed yet.");
        }

        RSA* rsaPubKey = RSA_new();
        BIO* bio = BIO_new_mem_buf(publicKey.data(), -1);
        PEM_read_bio_RSA_PUBKEY(bio, &rsaPubKey, nullptr, nullptr);

       unsigned char hash[SHA512_DIGEST_LENGTH];
        SHA512(reinterpret_cast<const unsigned char*>(txnHash.data()), txnHash.size(), hash);

        if (RSA_verify(NID_sha512, hash, SHA512_DIGEST_LENGTH,
                       reinterpret_cast<const unsigned char*>(signature->data()), signature->size(), 
                       rsaPubKey) != 1) {
            RSA_free(rsaPubKey);
            BIO_free(bio);
            throw SecureTransactionException("Transaction signature verification failed.");
        }

        RSA_free(rsaPubKey);
        BIO_free(bio);
    }

    std::string getTxnHash() const {
        return txnHash;
    }

    // HMAC تأیید یکپارچگی تراکنش
    std::string generateHMAC(const std::string& key, const std::string& data) {
    unsigned char* hmac = HMAC(EVP_sha512(), key.data(), key.size(),
        reinterpret_cast<const unsigned char*>(data.data()), data.size(),
        nullptr, nullptr);
    return std::string(reinterpret_cast<char*>(hmac), SHA512_DIGEST_LENGTH);
}
static void displayTransactionHistory() {
        std::cout << "Transaction History: " << std::endl;
        for (const auto& txn : transactionHistory) {
            std::cout << "Hash: " << txn.txnHash << ", Sender: " << txn.sender
                      << ", Receiver: " << txn.receiver << ", Value: " << txn.value 
                      << ", Timestamp: " << std::ctime(&txn.timestamp) 
                      << ", Nonce: " << txn.nonce 
                      << ", Signed: " << (txn.signedStatus ? "Yes" : "No") 
                      << ", Signature: " << txn.signature << std::endl;
        }
    }

private:
        void storeTransaction() {
        TransactionDetail txnDetail;
        txnDetail.txnHash = txnHash;
        txnDetail.sender = sender;
        txnDetail.receiver = receiver;
        txnDetail.value = value;
        txnDetail.timestamp = timestamp;
        txnDetail.nonce = nonce;
        txnDetail.signedStatus = signature.has_value();
        txnDetail.signature = signature.value_or("");

        transactionHistory.push_back(txnDetail);
    }

public:
    static std::vector<TransactionDetail> transactionHistory; // تاریخچه تراکنش‌ها

    Transaction(const std::string& sender, const std::string& receiver, double value, double transactionFee = 0.01,
                const std::string& assetId = "", TransactionType type = TransactionType::SIMPLE_TRANSFER)
        : sender(sender), receiver(receiver), value(value), assetId(assetId), type(type), transactionFee(transactionFee) {
        timestamp = std::time(nullptr);
        nonce = generateNonce(16); // تولید nonce
        std::string data = sender + receiver + std::to_string(value) + assetId + std::to_string(timestamp) + nonce;
        txnHash = generateHash(data);
    }

    static void displayTransactionHistory() {
        std::cout << "Transaction History: " << std::endl;
        for (const auto& txn : transactionHistory) {
            std::cout << "Hash: " << txn.txnHash << ", Sender: " << txn.sender
                      << ", Receiver: " << txn.receiver << ", Value: " << txn.value 
                      << ", Timestamp: " << std::ctime(&txn.timestamp) 
                      << ", Nonce: " << txn.nonce 
                      << ", Signed: " << (txn.signedStatus ? "Yes" : "No") 
                      << ", Signature: " << txn.signature << std::endl;
        }
    }
};

// تعریف مقدار اولیه برای تاریخچه تراکنش‌ها
std::vector<Transaction::TransactionDetail> Transaction::transactionHistory;

    // نمایش جزئیات تراکنش
    void displayTransaction() const {
        std::cout << "Transaction Details:" << std::endl;
        std::cout << "  Sender: " << sender << std::endl;
        std::cout << "  Receiver: " << receiver << std::endl;
        std::cout << "  Value: " << value << std::endl;
        std::cout << "  Asset ID: " << assetId << std::endl;
        std::cout << "  Timestamp: " << std::ctime(&timestamp); // زمان به فرمت رشته
        std::cout << "  Type: " << (type == TransactionType::SIMPLE_TRANSFER ? "Simple Transfer" : 
                                    type == TransactionType::NFT_TRANSFER ? "NFT Transfer" : "Coin Burn") << std::endl;
        std::cout << "  Transaction Hash: " << txnHash << std::endl;
        std::cout << "  Signature: " << signature << std::endl;
        std::cout << "  Verified: " << (isVerified ? "Yes" : "No") << std::endl;
    }

    // گیرایی هش تراکنش
    std::string getTransactionHash() const {
        return txnHash;
    }

    // وضعیت تأیید
    bool isTransactionVerified() const {
        return isVerified;
    }
  double getTotalSupply() const {
       return totalSupply;
   }
   
       // دسترسی به فرستنده و گیرنده
    std::string getSender() const { return sender; }
    std::string getReceiver() const { return receiver; }
    double getValue() const { return value; }
    std::string getAssetId() const { return assetId; }
    std::time_t getTimestamp() const { return timestamp; }
    TransactionType getType() const { return type; }

    // تابع برای تبدیل رویداد به رشته
    std::string getTransactionDetails() const {
        std::stringstream details;
        details << "Transaction from " << sender << " to " << receiver << "\n"
                << "Value: " << value << "\n"
                << "Asset ID: " << assetId << "\n"
                << "Type: " << (type == TransactionType::SIMPLE_TRANSFER ? "Simple Transfer" : 
                               type == TransactionType::NFT_TRANSFER ? "NFT Transfer" : "Coin Burn") << "\n"
                << "Timestamp: " << std::ctime(&timestamp)
                << "Hash: " << txnHash << "\n"
                << "Signature: " << signature << "\n"
                << "Verified: " << (isVerified ? "Yes" : "No") << "\n";
        return details.str();
    }
     void saveToDatabase(sqlite3* db) const {
        const char* sql = R"(INSERT INTO transactions (sender, receiver, value, transactionFee, assetId, type, timestamp, txnHash, status, memo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);)";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw TransactionException("Failed to prepare SQL statement");
        }

        sqlite3_bind_text(stmt, 1, sender.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, receiver.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_double(stmt, 3, value);
        sqlite3_bind_double(stmt, 4, transactionFee);
        sqlite3_bind_text(stmt, 5, assetId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 6, static_cast<int>(type));
        sqlite3_bind_int64(stmt, 7, timestamp);
        sqlite3_bind_text(stmt, 8, txnHash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 9, static_cast<int>(status));
        sqlite3_bind_text(stmt, 10, memo.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            throw TransactionException("Failed to execute SQL statement");
        }

        sqlite3_finalize(stmt);
    }

        static std::vector<Transaction> loadFromDatabase(sqlite3* db) {
        const char* sql = "SELECT sender, receiver, value, transactionFee, assetId, type, timestamp, txnHash, status, memo FROM transactions;";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw TransactionException("Failed to prepare SQL statement");
        }

        std::vector<Transaction> transactions;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            Transaction txn;
            txn.sender = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            txn.receiver = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            txn.value = sqlite3_column_double(stmt, 2);
            txn.transactionFee = sqlite3_column_double(stmt, 3);
            txn.assetId = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            txn.type = static_cast<TransactionType>(sqlite3_column_int(stmt, 5));
            txn.timestamp = sqlite3_column_int64(stmt, 6);
            txn.txnHash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            txn.status = static_cast<Status>(sqlite3_column_int(stmt, 8));
            txn.memo = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));

            transactions.push_back(txn);
        }

        sqlite3_finalize(stmt);
        return transactions;
    }
    void printDetails() const {
        std::cout << "--------------------------------------\n";
        std::cout << "Transaction Details:\n";
        std::cout << "Sender: " << sender << "\n";
        std::cout << "Receiver: " << receiver << "\n";
        std::cout << "Value: " << value << "\n";
        std::cout << "Transaction Fee: " << transactionFee << "\n";
        std::cout << "Asset ID: " << assetId << "\n";
        std::cout << "Type: " << static_cast<int>(type) << "\n";
        std::cout << "Timestamp: " << std::put_time(std::localtime(&timestamp), "%Y-%m-%d %H:%M:%S") << "\n"; // فرمت زمان
        std::cout << "Transaction Hash: " << txnHash << "\n";
        std::cout << "Status: " << static_cast<int>(status) << "\n"; // یا متن مناسب
        std::cout << "Memo: " << memo << "\n";
        std::cout << "--------------------------------------\n";
    }
    
// تعریف متغیر استاتیک
std::list<Transaction::TransactionDetail> Transaction::transactionHistory;
return 0;
};
class Block {
private:
    std::string previousHash;
    std::unordered_map<std::string, Transaction> transactions;
    std::string blockHash;
    int nonce;
    std::time_t timestamp;
    int difficulty;
    std::vector<std::string> log;

    void logEvent(const std::string& event) {
        log.push_back(event);
    }

public:
    Block(const std::string& previousHash, int difficulty) 
        : previousHash(previousHash), nonce(0), difficulty(difficulty) {
        timestamp = std::time(nullptr);
        logEvent("Block created with previous hash: " + previousHash);
    }

    void addTransaction(const Transaction& txn) {
        if (transactions.count(txn.sender + txn.receiver) > 0) {
            logEvent("Transaction already exists, replacing: " + txn.serialize());
        }
        transactions[txn.sender + txn.receiver] = txn;
        logEvent("Transaction added: " + txn.serialize());
    }

    std::string calculateHash() {
        std::ostringstream os;
        os << previousHash << timestamp << nonce;

        for (const auto& pair : transactions) {
            os << pair.second.serialize();
        }

        return hashString(os.str());
    }

    std::string hashString(const std::string& input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

        std::ostringstream result;
        for (auto byte : hash) {
            result << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return result.str();
    }

    void mineBlock(int targetTime) {
        auto start = std::chrono::system_clock::now();
        std::string target(difficulty, '0');

        do {
            nonce++;
            blockHash = calculateHash();

            auto end = std::chrono::system_clock::now();
            double elapsed_seconds = std::chrono::duration<double>(end - start).count();

            if (elapsed_seconds >= targetTime) {
                difficulty = (elapsed_seconds > targetTime) ? std::max(1, difficulty - 1) : difficulty + 1;
                logEvent("Difficulty adjusted to: " + std::to_string(difficulty));
                break;
            }
        } while (blockHash.substr(0, difficulty) != target);

        std::cout << "Block mined: " << blockHash << std::endl;
        logEvent("Block mined with hash: " + blockHash);
    }    void displayBlock() const {
        std::cout << "Previous Hash: " << previousHash << std::endl;
        std::cout << "Block Hash: " << blockHash << std::endl;
        std::cout << "Timestamp: " << std::ctime(&timestamp);
        std::cout << "Transactions:" << std::endl;

        for (const auto& pair : transactions) {
            const Transaction& txn = pair.second;
            std::cout << "  - " << txn.sender << " -> "
                      << txn.receiver << ": " << txn.value << " at "
                      << std::ctime(&txn.timestamp);
        }
        
        std::cout << "Log:" << std::endl;
        for (const auto& entry : log) {
            std::cout << "  - " << entry << std::endl;
        }
    }

    // Additional methods for retrieving block information
    std::string getHash() const {
        return blockHash;
    }

    std::string getPreviousHash() const {
        return previousHash;
    }

    const std::unordered_map<std::string, Transaction>& getTransactions() const {
        return transactions;
    }

    int getNonce() const {
        return nonce;
    }

    void setDifficulty(int newDifficulty) {
        difficulty = newDifficulty;
    }

    int getDifficulty() const {
        return difficulty;
    }

    std::time_t getTimestamp() const {
        return timestamp;
    }
    void addTransaction(const Transaction& txn) {
        if (transactions.count(txn.sender + txn.receiver) > 0) {
            logEvent("Transaction already exists, replacing: " + txn.serialize());
        }
        transactions[txn.sender + txn.receiver] = txn;
        logEvent("Transaction added: " + txn.serialize());
    }

    std::string calculateHash() {
        std::ostringstream os;
        os << previousHash << timestamp << nonce;

        for (const auto& pair : transactions) {
            os << pair.second.serialize();
        }

        return hashString(os.str());
    }

    std::string hashString(const std::string& input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

        std::ostringstream result;
        for (auto byte : hash) {
            result << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return result.str();
    }

    void mineBlock(int targetTime) {
        auto start = std::chrono::system_clock::now();
        std::string target(difficulty, '0');

        do {
            nonce++;
            blockHash = calculateHash();

            auto end = std::chrono::system_clock::now();
            double elapsed_seconds = std::chrono::duration<double>(end - start).count();

            // تنظیم سختی بر اساس زمان
            if (elapsed_seconds >= targetTime) {
                difficulty = std::max(1, difficulty - 1); // اگر زمان بیشتر از حد مشخص بود، سختی کاهش یابد
                logEvent("Difficulty increased.");
            } else {
                difficulty++; // در غیر این صورت سختی افزایش یابد
            }

        } while (blockHash.substr(0, difficulty) != target);

        logEvent("Block mined: " + blockHash);
    }

    // متد بارگذاری از فایل
    void loadFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open file to load block.");
        }

        transactions.clear();
        log.clear();

        std::getline(file, previousHash);
        std::getline(file, blockHash);

        // پارس timestamp
        std::string timestampLine;
        std::getline(file, timestampLine);
        timestamp = std::stoll(timestampLine); 

        std::string line;
        while (std::getline(file, line)) {
            if (line.find("Transactions:") == std::string::npos && line.find("Log:") == std::string::npos) {
                std::istringstream ss(line);
                std::string sender, receiver;
                double value;
                std::time_t txnTimestamp;

                ss >> sender >> receiver >> value >> txnTimestamp;

                Transaction txn(sender, receiver, value);
                transactions[txn.sender + txn.receiver] = txn;
            } else if (line.find("Log:") != std::string::npos) {
                break;  // پایان بخش تراکنش
            }
        }

        // خواندن لاگ‌ها
        while (std::getline(file, line)) {
            log.push_back(line);
        }

        file.close();
    }

    // متد برای نمایش لاگ‌ها
    void printLog() const {
        for (const auto& entry : log) {
            std::cout << entry << std::endl;
        }
    }

    // متد برای نمایش تراکنش‌ها
    void printTransactions() const {
        for (const auto& pair : transactions) {
            std::cout << pair.second.serialize() << std::endl;
        }
    }
};
class NFT {
public:
    struct OwnershipHistory {
        std::string owner;
        std::time_t timestamp;

        OwnershipHistory(const std::string& ownerId)
            : owner(ownerId), timestamp(std::time(nullptr)) {}
    };

    struct Review {
        std::string reviewer;
        std::string comment;
        std::time_t timestamp;

        Review(const std::string& rev, const std::string& comm)
            : reviewer(rev), comment(comm), timestamp(std::time(nullptr)) {}
    };

    struct Transaction {
    std::string from;
    std::string to;
    std::time_t timestamp;
    std::string transactionId;

    Transaction(const std::string& fromOwner, const std::string& toOwner, const std::string& txId)
        : from(fromOwner), to(toOwner), timestamp(std::time(nullptr)), transactionId(txId) {}
};

    struct Auction {
    std::string highestBidder;
    double highestBid;
    std::time_t endTime;

    Auction(double startingBid, int durationSeconds)
        : highestBid("None"), highestBid(startingBid), endTime(std::time(nullptr) + durationSeconds) {}
};

private:
    std::string assetId;
    std::string owner;
    std::string metadata;
    std::vector<OwnershipHistory> history;
    std::vector<Review> reviews;
    std::unordered_map<std::string, bool> permissions;
    std::vector<Transaction> transactions;
    std::vector<std::string> tags;
    std::unique_ptr<Auction> currentAuction;

    std::string generateHash(const std::string& input) const {
        unsigned char hash[SHA512_DIGEST_LENGTH];
            
                    SHA512(reinterpret_cast<unsigned char*>(hash), reinterpret_cast<const unsigned char*>(input.c_str()), input.size() hash );
     

        std::stringstream hashStream;
        for (unsigned char byte : hash) {
            hashStream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte);
        }
        return hashStream.str();
    }

public:
    NFT(const std::string& id, const std::string& ownerId, const std::string& meta)
        : assetId(id), owner(ownerId), metadata(meta), currentAuction(nullptr) {
        history.emplace_back(ownerId);
        permissions[ownerId] = true;
    }

    void transferOwnership(const std::string& newOwner) {
    // بررسی مجوزها برای انتقال مالکیت
    if (permissions.find(owner) != permissions.end()) {
        std::string txId = generateHash(assetId + owner + newOwner + std::to_string(std::time(nullptr)));
        transactions.emplace_back(owner, newOwner, txId);
        history.emplace_back(newOwner);
        permissions[newOwner] = true;
        permissions[history[history.size() - 2].owner] = false;
        owner = newOwner;
        std::cout << "Ownership transferred to " << newOwner << " with Transaction ID: " << txId << std::endl;
    } else {
        std::cout << "Permission denied for transfer." << std::endl;
    }
}

    void startAuction(double startingBid, int durationSeconds) {
    if (currentAuction == nullptr) {
        currentAuction = std::unique_ptr Auction(startingBid, durationSeconds);
        std::cout << "Auction started with starting bid: " << startingBid << std::endl;
    } else {
        std::cout << "An auction is already in progress." << std::endl;
    }
}
    void placeBid(const std::string& bidder, double bidAmount) {
    if (currentAuction == nullptr) {
        std::cout << "No auction is currently in progress." << std::endl;
        return;
    }
    if (std::time(nullptr) > currentAuction->endTime) {
        std::cout << "Auction has ended." << std::endl;
        delete currentAuction;
        currentAuction = nullptr;
        return;
    }
    if (bidAmount <= currentAuction->highestBid) {
        std::cout << "Bid amount must be higher than the current highest bid." << std::endl;
        return;
    }

    currentAuction->highestBidder = bidder;
    currentAuction->highestBid = bidAmount;
    std::cout << "Bid placed by " << bidder << " for " << bidAmount << " ICKG." << std::endl;
}

    void endAuction() {
    if (currentAuction == nullptr) {
        std::cout << "No auction is currently in progress." << std::endl;
        return;
    }
    if (std::time(nullptr) <= currentAuction->endTime) {
        std::cout << "Auction is still ongoing." << std::endl;
        return;
    }

    std::cout << "Auction ended. Highest bidder: " 
              << currentAuction->highestBidder << " with amount: "
              << currentAuction->highestBid << " ICKG." << std::endl;

    if (currentAuction->highestBidder != "None") {
        transferOwnership(currentAuction->highestBidder);
    }

    delete currentAuction;
    currentAuction = nullptr;
}
    void addReview(const std::string& reviewer, const std::string& comment) {
        reviews.emplace_back(reviewer, comment);
        std::cout << "Review added by " << reviewer << std::endl;
    }

    void addTag(const std::string& tag) {
        tags.push_back(tag);
        std::cout << "Tag added: " << tag << std::endl;
    }

    std::vector<NFT> searchByTags(const std::vector<NFT>& nftCollection, const std::string& tag) const {
        std::vector<NFT> results;
        for (const auto& nft : nftCollection) {
            if (std::find(nft.tags.begin(), nft.tags.end(), tag) != nft.tags.end()) {
                results.push_back(nft);
            }
        }
        return results;
    }

        void displayDetails() const {
        std::cout << "NFT Details:" << std::endl;
        std::cout << "  Asset ID: " << assetId << std::endl;
        std::cout << "  Current Owner: " << owner << std::endl;
        std::cout << "  Metadata: " << metadata << std::endl;

        std::cout << "  Ownership History: " << std::endl;
        for (const auto& historyEntry : history) {
            std::cout << "    - " << historyEntry.owner << " at " << std::ctime(&historyEntry.timestamp);
        }

        if (currentAuction) {
            std::cout << "  Current Auction: " << std::endl;
            std::cout << "    Highest Bid: " << currentAuction->highestBid << " from " << currentAuction->highestBidder << std::endl;
            std::cout << "    Ends at: " << std::ctime(&currentAuction->endTime);
        }
    }
};


class Wallet {
public:
    std::string ownerId;
    double balance;

    Wallet(const std::string& id) : ownerId(id), balance(0) {}

    void addBalance(double amount) {
        if (amount < 0) {
            throw std::invalid_argument("Cannot add a negative amount.");
        }
        balance += amount;
    }

    void subtractBalance(double amount) {
        if (amount < 0) {
            throw std::invalid_argument("Cannot subtract a negative amount.");
        }
        if (balance < amount) {
            throw std::runtime_error("Insufficient balance.");
        }
        balance -= amount;
    }

    double getBalance() const {
        return balance;
    }
};

enum class ContractStatus {
    RUNNING,
    COMPLETED,
    CANCELED
    User(const std::string& name, const std::string& id) : username(name), userID(id) {}
};

class SmartContract {
public:
    std::string contractId;
    std::unordered_map<std::string, std::function<void(const std::unordered_map<std::string, std::string>&)>> actions;
    std::unordered_map<std::string, std::string> state;
    std::vector<std::string> eventLog;
    ContractStatus status;

    SmartContract(const std::string& id) : contractId(id), status(ContractStatus::RUNNING) {}

    void addAction(const std::string& actionName, const std::function<void(const std::unordered_map<std::string, std::string>&)>& func) {
        actions[actionName] = func;
    }

    void run(const std::string& actionName, const std::unordered_map<std::string, std::string>& inputs) {
        if (status == ContractStatus::CANCELED) {
            throw std::runtime_error("Cannot execute cancelled contract.");
        }

        try {
            if (actions.find(actionName) == actions.end()) {
                throw std::runtime_error("Action not found: " + actionName);
            }
            actions[actionName](inputs);
            status = ContractStatus::COMPLETED;
            logEvent("Contract executed successfully for action: " + actionName);
        } catch (const std::exception& e) {
            status = ContractStatus::CANCELED;
            logEvent("Execution failed for action: " + actionName + ". Error: " + std::string(e.what()));
        }
    }

    void cancel() {
        status = ContractStatus::CANCELED;
        logEvent("Contract has been cancelled.");
    }

    void logEvent(const std::string& event) {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X") << " - " << event;
        eventLog.push_back(oss.str());
        std::cout << "Event: " << event << std::endl;
    }

    void setState(const std::string& key, const std::string& value) {
        state[key] = value;
        logEvent("State updated: " + key + " = " + value);
    }

    std::string getState(const std::string& key) const {
        auto it = state.find(key);
        if (it != state.end()) {
            return it->second;
        }
        return ""; // در صورتی که کلید وجود نداشته باشد، رشته خالی برمی‌گرداند
    }

    void displayState() const {
        std::cout << "Contract State:\n";
        for (const auto& pair : state) {
            std::cout << "  " << pair.first << ": " << pair.second << "\n";
        }
    }

    void displayEventLog() const {
        std::cout << "Event Log:\n";
        for (const auto& event : eventLog) {
            std::cout << "  " << event << "\n";
        }
    }

    std::string getContractId() const {
        return contractId;
    }

    ContractStatus getStatus() const {
        return status;
    }
};

// یک مثال از استفاده از SmartContract با ورودی‌های چندنوعی و چند عمل
int main() {
    SmartContract myContract("Contract1");

    // افزودن توابع مختلف به قرارداد
        myContract.addAction("increment", [](const std::unordered_map<std::string, std::string>& inputs) {
        if (inputs.count("value") == 0) {
            throw std::runtime_error("No value provided for increment.");
        }
        int currentValue = std::stoi(inputs.at("value"));
        std::cout << "Incrementing value to: " << (currentValue + 1) << std::endl;
    });

    myContract.addAction("decrement", [](const std::unordered_map<std::string, std::string>& inputs) {
        if (inputs.count("value") == 0) {
            throw std::runtime_error("No value provided for decrement.");
        }
        int currentValue = std::stoi(inputs.at("value"));
        std::cout << "Decrementing value to: " << (currentValue - 1) << std::endl;
    });

    myContract.addAction("setValue", [](const std::unordered_map<std::string, std::string>& inputs) {
        if (inputs.count("value") == 0) {
            throw std::runtime_error("No value provided to set.");
        }
        std::cout << "Setting value to: " << inputs.at("value") << std::endl;
    });

    // ورودی‌ها برای افزایش مقدار
    std::unordered_map<std::string, std::string> inputs;
    
    // افزایش مقدار
    inputs["value"] = "5"; // مقدار اولیه 5
    myContract.run("increment", inputs);
    
    // کاهش مقدار
    myContract.run("decrement", inputs);
    
    // تنظیم مقدار
    inputs["value"] = "10"; // مقدار جدید
    myContract.run("setValue", inputs);
    
    // نمایش وضعیت فعلی قرارداد
    myContract.displayState();

    // تلاش برای اجرای کنسل شده
    myContract.cancel();
    void displayEventLog() const {
        std::cout << "Event Log for Contract " << contractId << ":\n";
        for (const auto& event : eventLog) {
            std::cout << "  " << event << "\n";
        }
    }

    std::string getContractId() const {
        return contractId;
    }

    ContractStatus getStatus() const {
        return status;
    }
};

               
class Coin {
private:
    Blockchain blockchain;

    Coin(int difficulty) : blockchain(difficulty) {}

    
    std::string name;
    std::string symbol;
    double totalSupply;
    int decimalPlaces;
    double marketSupply;
    std::unordered_map<std::string, std::shared_ptr<Wallet>> wallets;
    std::vector<Transaction> transactionHistory; // تاریخچه تراکنش‌ها

public:
    Coin(const std::string& coinName, const std::string& coinSymbol, double supply, int decimals)
        : name(coinName), symbol(coinSymbol), totalSupply(supply), decimalPlaces(decimals), marketSupply(0) {}

    // البته بیشتر کردم تا از تورم و فساد مالی و جلوگیری از هرگونه سوء استفادهBurn کردن کوین (حذف 0.01 درصد از عرضه بازار)
    void burn() {
        double amountToBurn = marketSupply * 0.00001; // 0.01% از عرضه بازار
        if (marketSupply < amountToBurn) {
            throw std::runtime_error("Cannot burn more than the available supply.");
        }
        marketSupply -= amountToBurn;
        std::cout << amountToBurn << " " << symbol << " burned. Total Market Supply: " << marketSupply << std::endl;
    }

    // ایجاد کیف پول جدید
    void createWallet(const std::string& ownerId) {
        if (wallets.find(ownerId) != wallets.end()) {
            throw std::runtime_error("Wallet already exists.");
        }
        wallets[ownerId] = std::make_shared<Wallet>(ownerId);
        std::cout << "Wallet created for: " << ownerId << std::endl;
    }

    // انتقال کوین بین کیف‌پول‌ها
    void transfer(const std::string& senderId, const std::string& receiverId, double amount) {
        if (wallets.find(senderId) == wallets.end() || wallets.find(receiverId) == wallets.end()) {
            throw std::runtime_error("One or both wallets do not exist.");
        }
        if (amount <= 0) {
            throw std::runtime_error("Transfer amount must be positive.");
        }

        // تأیید موجودی به اندازه کافی
        wallets[senderId]->subtractBalance(amount);
        wallets[receiverId]->addBalance(amount);

        // ثبت تراکنش
        transactionHistory.push_back(Transaction(senderId, receiverId, amount));
        std::cout << "Transferred " << amount << " " << symbol << " from " << senderId << " to " << receiverId << std::endl;
    }

    // دریافت موجودی کیف‌پول
    double getWalletBalance(const std::string& ownerId) const {
        if (wallets.find(ownerId) != wallets.end()) {
            return wallets.at(ownerId)->getBalance();
        }
        throw std::runtime_error("Wallet does not exist.");
    }
void createTransaction(const std::string& sender, const std::string& receiver, double amount) {
        if (amount <= 0) {
            std::cerr << "Invalid transaction amount: " << amount << std::endl;
            return;
        }
        Transaction newTransaction(sender, receiver, amount);
        blockchain.addBlock({ newTransaction });
    }
    // نمایش تاریخچه تراکنش‌ها
    void displayTransactionHistory() const {
        std::cout << "Transaction History:" << std::endl;
        for (const auto& tx : transactionHistory) {
            std::cout << "From: " << tx.from << ", To: " << tx.to << ", Amount: " << tx.amount << " " << symbol << std::endl;
        }
    }

    // دریافت کل عرضه کوین
    double getTot const {
        return totalSupply;
    }

    // دریافت عرضه بازار
    double getMarketSupply() const {
        return marketSupply;
    }
    // دریافت نام کوین
    std::string getName() const {
        return name;
    }

    // دریافت نماد کوین
    std::string getSymbol() const {
        return symbol;
    }

    // دریافت تعداد اعشار کوین
    int getDecimalPlaces() const {
        return decimalPlaces;
    }

    // دریافت موجودی کیف‌پول به صورت متن
    std::string getWalletInfo(const std::string& ownerId) const {
        if (wallets.find(ownerId) != wallets.end()) {
            return "Wallet Owner: " + ownerId + ", Balance: " + std::to_string(wallets.at(ownerId)->getBalance()) + " " + symbol;
        }
        throw std::runtime_error("Wallet does not exist.");
} 
    }; 
classNetworkError:publicstd::runtime_error{
public:
NetworkError(conststd::string&msg):std::runtime_error(msg){}
};
class Blockchain {
public:
    LightningNetworklightningNetwork;
std::vector<Block> blocks;
std::vector<SmartContract> contracts;
    std::unordered_map<std::string, User> users;


    
    std::vector<Transaction> currentTransactions;
    std::unordered_map<std::string, std::shared_ptr<Wallet>> wallets;
    std::unordered_map<std::string, NFT> nfts;
    Coin iceKingCoin;

public:
    Blockchain() 
    Blockchain(int difficulty = 12, double reward = 1.0, double maxSupply = 210000000.0) 
        : difficulty(difficulty), reward(reward), totalSupply(0.0), maxSupply(maxSupply) {
        chain.emplace_back("0", difficulty); // بلاک صفر (genesis block)
        std::cout << "Genesis block created." << std::endl;
        : iceKingCoin("ICE KING", "ICKG", 210000000, 25){
        
    }
    void createGenesisBlock() {
        std::vector<Transaction> genesisTransactions;
        createBlock("0", genesisTransactions);
    }

    void createBlock(const std::string& previousHash, const std::vector<Transaction>& transactions) {
        int newIndex = blocks.size();
        blocks.emplace_back(newIndex, previousHash, transactions);
    }
     void mineBlock() {
        if (totalSupply + reward > maxSupply) {
            throw std::runtime_error("Cannot mine more coins than max supply.");
        }

        Block newBlock(chain.back().getHash(), difficulty);
        newBlock.mineBlock(300); // استخراج بلاک با زمان هدف 300/600 ثانیه
        totalSupply += reward; 
        chain.push_back(newBlock);
        std::cout << "Block added to blockchain." << std::endl;
    }

    
void registerUser(const std::string& username, const std::string& userID) {
        users[userID] = User(username, userID);
        std::cout << "User registered: " << username << " with ID: " << userID << std::endl;
    }

    void addContract(const std::string& userID, const SmartContract& contract) {        if (users.find(userID) == users.end()) {
            throw std::runtime_error("User not found: " + userID);
        }
        contracts.push_back(contract);
        std::cout << "Contract added for user " << users[userID].username << ": " << contract.getContractId() << std::endl;
    }

    SmartContract* getContractById(const std::string& contractId) {
        for (auto& contract : contracts) {
            if (contract.getContractId() == contractId) {
                return &contract;
            }
        }
        return nullptr; // در صورتی که قرارداد پیدا نشود
    }

    void displayAllContracts() const {
        std::cout << "Registered Contracts:\n";
        for (const auto& contract : contracts) {
            std::cout << "  Contract ID: " << contract.getContractId() 
                      << ", Status: " << static_cast<int>(contract.getStatus()) << "\n";
        }
    }
    void addTransaction(const std::string& sender, const std::string& receiver, double value, const std::string& assetId) {
        if (wallets.find(sender) == wallets.end() || wallets.find(receiver) == wallets.end()) {
            throw std::runtime_error("Wallet does not exist.");
        }

        Transaction newTransaction(sender, receiver, value, assetId);
        currentTransactions.push_back(newTransaction);

        // بررسی برای ایجاد بلاک جدید بعد از 100 تراکنش
        if (currentTransactions.size() >= 100) {
            std::string chosenValidator = selectValidator();
            if (!chosenValidator.empty()) {
                performWork(chosenValidator); // اجرای کار قبل از تولید بلاک
                createBlock(blocks.back().computeHash(), currentTransactions);
                currentTransactions.clear(); // پاک‌سازی تراکنش‌های جاری
                std::cout << "New block created by: " << chosenValidator << std::endl;
            }
        }
    }

    void voteForValidator(const std::string& voterId, const std::string& validatorId) {
        if (wallets.find(voterId) == wallets.end() || wallets.find(validatorId) == wallets.end()) {
            throw std::runtime_error("Wallet does not exist.");
        }
        votes[validatorId].push_back(voterId); // ثبت رأی
        std::cout << voterId << " voted for " << validatorId << std::endl;
    }

    std::string selectValidator() {
        // برای ساده‌سازی، نماینده‌ای که بیشترین رأی را دارد انتخاب می‌شود
        std::string selectedValidator;
        size_t maxVotes = 0;

        for (const auto& pair : votes) {
            if (pair.second.size() > maxVotes) {
                maxVotes = pair.second.size();
                selectedValidator = pair.first;
            }
        }

        return selectedValidator;
    }
void create LightningChannel(conststd::string&userA,conststd::string&userB,doubleinitialBalanceA,doubl einitial BalanceB){
lightning Network.createChannel(userA,userB,initialBalanceA,initial BalanceB);
}
void transferIn Lightning(conststd::string&sender,conststd::string&receiver,doubleamount){
lightningNetwork.transfer(sender,receiver,amount);
}
    void performWork(const std::string& validatorId) {        std::cout << "Validator " << validatorId << " is performing work..." << std::endl;
        // در اینجا می‌توانید کد محاسباتی واقعی را اضافه کنید.
        // برای سادگی، از یک تأخیر استفاده می‌کنیم.
        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // شبیه‌سازی کار
        std::cout << "Work completed by " << validatorId << "!" << std::endl;
    }


    void displayVotes() const {
        std::cout << "Votes for Validators:" << std::endl;
        for (const auto& pair : votes) {
            std::cout << "  Validator: " << pair.first << " Votes: " << pair.second.size() << std::endl;
        }
    }
}; 

    void addTransaction(const std::string& sender, const std::string& receiver, double value, const std::string& assetId) {
        if (wallets.find(sender) == wallets.end() || wallets.find(receiver) == wallets.end()) {
            throw std::runtime_error("Wallet does not exist.");
        }
        // ایجاد تراکنش و ذخیره آن
        Transaction newTransaction(sender, receiver, value, assetId);
        currentTransactions.push_back(newTransaction);
        // احتمالا بعد از این بروزرسانی بلاک نیز ایجاد شود
    }

private:
    std::vector<Block> blocks; // تعریف بلاک‌ها
    std::vector<Transaction> currentTransactions; // تعریف تراکنش‌های جاری
    std::unordered_map<std::string,std::unique_ptr<Wallet>> wallets; // تعریف کیف پول‌ها
    std::unordered_map<std::string, NFT> nfts; // تعریف NFT‌ها
};

    void displayWallets() const {
        std::cout << "Wallets:" << std::endl;
        for (const auto& pair : wallets) {
            const Wallet& wallet = *pair.second;
            std::cout << "  Owner ID: " << wallet.ownerId 
                      << " Balance: " << wallet.balance << std::endl;
        }
    }

    void displayNFTs() const {
        std::cout << "NFTs in the blockchain:" << std::endl;
        for (const auto& pair : nfts) {
            const NFT& nft = pair.second;
            std::cout << "  Asset ID: " << nft.assetId 
                      << " Owner: " << nft.owner 
                      << " Metadata: " << nft.metadata << std::endl;
        }
    }
void displayBlockchain() const {
        std::cout << "Blockchain:" << std::endl;
        for (const auto& block : blocks) {
            std::cout << "  Block " << block.index << " (Hash: " << block.computeHash() << ")" << std::endl;
            for (const auto& transaction : block.transactions) {
                std::cout << "    Transaction: " << transaction.sender << " -> " << transaction.receiver 
                          << " Asset: " << transaction.assetId << " Value: " << transaction.value << std::endl;
            }
        }
    }
    void displayChain() const {
        std::cout << "Blockchain:" << std::endl;
        for (const auto& block : chain) {
            block.displayBlock();
            std::cout << std::endl;
        }
    }

    double getTotalSupply() const {
        return totalSupply;
    }

    std::string getCoinName() const {
        return "ICE KING (ICKG)";
    }
private:
    std::vector<Block> blocks;
    std::vector<Transaction> currentTransactions;
    std::unordered_map<std::string, NFT> nfts;
    std::unordered_map<std::string, std::unique_ptr<Wallet>> wallets;
};
void transferNFT(const std::string& assetId, const std::string& newOwner) {
    if (nfts.find(assetId) != nfts.end()) {
        nfts[assetId].transferOwnership(newOwner);
    } else {
        throw std::runtime_error("NFT does not exist.");
    }
}
void createWallet(const std::string& ownerId) {
    if (wallets.find(ownerId) != wallets.end()) {
        throw std::runtime_error("Wallet already exists.");
    }
    wallets[ownerId] = std::make_unique<Wallet>(ownerId);
}

    Blockchain blockchain; 
    };