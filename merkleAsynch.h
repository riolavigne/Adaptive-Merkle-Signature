#include <mutex>

class MerkleAsynch : public Merkle {
  public:
    //using Merkle::Merkle;
    MerkleAsynch(Data sk, unsigned int depth, unsigned int ell, bool isBottom) : Merkle(sk, depth, ell, isBottom){};

  protected:
    std::mutex msgLock;
    virtual long getNextMsg() {
      std::lock_guard<std::mutex> lg(msgLock);
      long msgNum = msg.ConvertToLong();
      msg++;
      return msgNum;
    }
};
