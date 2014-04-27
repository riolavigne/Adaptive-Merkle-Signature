//adaptiveMerkle.h
#include <functional>

#include "merkle.h"
class AdaptiveMerkle {
  public:
    typedef std::vector<Merkle::Signature> Signature;

    // Constructor is also setup/keygen
    AdaptiveMerkle(std::vector<unsigned int> treeSizesIn, Data sk,
        std::vector<unsigned int> ellIn);
    ~AdaptiveMerkle();
    // returns root of pk
    Data getPublicKey();
    // Encodes the parameters into a string; mainly for debugging
    std::string toString();

    // Signs a digest -- sk is stored in the structure
    AdaptiveMerkle::Signature sign(Data digest);
    // returns the number of messages that can still be signed by the object
    CryptoPP::Integer getMessagesLeft();
    // Returns the total size of the structure in bytes
    CryptoPP::Integer getSize();

    // --- static methods --- //
    static bool verify(Data digest, AdaptiveMerkle::Signature sig, Data publicKey, std::vector<unsigned int> ell);
    // calculates what the pk should be given the digest
    static Data calculatePublicKey(Data digest, AdaptiveMerkle::Signature sig, std::vector<unsigned int> ell);

  private:
    Data secretKey;
    std::vector<unsigned int> treeSizes;
    std::vector<Merkle> exist;
    std::vector<Merkle> desired;
    unsigned int state; // State for creating trees (not msg number)
    AdaptiveMerkle::Signature sig; // the signature is updated after each message
    std::vector<unsigned int> ell; // ell parameters for winternitz
    // Integers to keep track of how many messages the trees can sign in total and how many messages are left
    CryptoPP::Integer msgsLeft;

    // Initializes a merkle tree of specified depth, ell, and a
    // boolean to tell if the tree is a bottom tree or not.
    Merkle initTree(unsigned int depth, unsigned int ell);
    // Initializes the first signature. Signature stored in memory and
    // updated with each signing.
    void initSig();
    // Updates the signature and tree structure when signing a message
    // Requires the message digest to update the signature.
    void update(Data digest);
    // Initializes a tree at level treeNum
    void initialize(unsigned int treeNum);
    // Resets a desired tree to an empty tree at level treeNum
    void reset(unsigned int treeNum);
};
