#ifndef DCCOMMS_EXAMPLES_DCMAC_H
#define DCCOMMS_EXAMPLES_DCMAC_H

#include <chrono>
#include <cpplogging/cpplogging.h>
#include <cpputils/RelativeTime.h>
#include <dccomms/dccomms.h>
#include <dccomms_packets/SimplePacket.h>
#include <dccomms_packets/VariableLengthPacket.h>
#include <iostream>

using namespace dccomms;
using namespace std;
using namespace dccomms_packets;
using namespace std::chrono;
using namespace cpputils;

namespace umci {

typedef uint8_t DcMacInfoField;
typedef uint8_t DcMacPSizeField;
typedef uint16_t DcMacRtsDataSizeField;
typedef uint8_t DcMacAckField;

class DcMacPacket : public Packet {
public:
  enum Type { sync = 0, rts, cts, data, unknown };
  DcMacPacket();
  void SetDcMacDst(uint8_t add);
  void SetDcMacSrc(uint8_t add);
  void SetType(Type type);
  Type GetType();
  void SetRtsDataSize(const DcMacRtsDataSizeField &tt);
  DcMacRtsDataSizeField GetRtsDataSize();
  bool GetSlaveAck(uint8_t node);
  DcMacAckField GetSlaveAckMask();

  uint8_t GetDcMacDst();
  uint8_t GetDcMacSrc();
  void SetMasterAckMask(const DcMacAckField &mask);
  void SetSlaveAck(uint8_t node);
  void SetSlaveAckMask(const DcMacAckField &mask);

  uint8_t GetMasterAckMask();

  static int GetPayloadSizeFromPacketSize(int size);

  void SetDst(const uint32_t & addr) { SetDcMacDst(addr); }
  void SetSrc(const uint32_t & addr) { SetDcMacSrc(addr); }

  uint32_t GetDst() { return GetDcMacDst(); }
  uint32_t GetSrc() { return GetDcMacSrc(); }

  void DoCopyFromRawBuffer(void *buffer);
  uint8_t *GetPayloadBuffer();
  uint32_t GetPayloadSize();
  int GetPacketSize();
  void Read(Stream *comms);
  void PayloadUpdated(uint32_t payloadSize);
  uint32_t SetPayload(uint8_t *data, uint32_t size);

  bool IsOk();
  PacketPtr Create();

  void UpdateFCS();
  static const int PRE_SIZE = 1, ADD_SIZE = 1, FLAGS_SIZE = 1,
                   CTSRTS_FIELD_SIZE = 2, PAYLOAD_SIZE_FIELD_SIZE = 1,
                   MAX_PAYLOAD_SIZE = 2048, SYNC_FIELD_SIZE = 1,
                   FCS_SIZE = 2; // CRC16
private:
  int _maxPacketSize;
  int _overheadSize;
  uint8_t *_pre;
  DcMacInfoField *_add;
  DcMacInfoField *_flags;
  uint8_t *_rtsSizeByte0, *_rtsSizeByte1;
  DcMacAckField *_slaveAckMask;
  DcMacPSizeField *_payloadSize;
  DcMacInfoField *_masterAckMask;
  uint8_t *_variableArea;
  uint8_t *_payload;
  uint8_t *_fcs;
  int _prefixSize;
  Type _GetType(uint8_t *flags);
  void _SetType(uint8_t *flags, Type type);
  uint16_t _GetRtsDataSize();
  void _Init();
  bool _CheckFCS();
  inline int _GetTypeSize(Type type, uint8_t *buffer);
  inline void _SetPayloadSizeField(uint16_t);
  inline uint16_t _GetPayloadSizeFromBuffer(uint8_t *buffer);
};

typedef std::shared_ptr<DcMacPacket> DcMacPacketPtr;

class DcMacPacketBuilder : public IPacketBuilder {
public:
  dccomms::PacketPtr CreateFromBuffer(void *buffer) {
    auto pkt = dccomms::CreateObject<DcMacPacket>();
    pkt->CopyFromRawBuffer(buffer);
    return pkt;
  }
  dccomms::PacketPtr Create() { return dccomms::CreateObject<DcMacPacket>(); }
};

class DcMac : public CommsDeviceService {
public:
  enum Mode { master, slave };
  enum Status {
    waitrts,
    waitcts,
    waitdata,
    waitack,
    idle,
    ackreceived,
    syncreceived,
    waitnextcycle,
    ctsreceived,
    rtsreceived,
    datareceived
  };
  DcMac();
  void SetAddr(const uint16_t &addr);
  uint16_t GetAddr();
  void SetMode(const Mode &mode);
  void SetNumberOfNodes(const uint16_t num);
  Mode GetMode();
  void Start();
  void SetRtsSlotDur(const uint32_t &slotdur);
  void SetMaxDataSlotDur(const uint32_t &slotdur);
  void SetDevBitRate(const uint32_t &bitrate);    // bps
  void SetDevIntrinsicDelay(const double &delay); // millis
  void SetPropSpeed(const double &propspeed);     // m/s
  void SetMaxDistance(const double &distance);    // m
  void UpdateSlotDurFromEstimation();
  double GetPktTransmissionMillis(const uint32_t &size);
  void SetPktBuilder(const PacketBuilderPtr &pb);
  virtual void SetCommsDeviceId(std::string nspace) override;

  virtual void ReadPacket(const PacketPtr &pkt) override;
  virtual void WritePacket(const PacketPtr &pkt) override;

  // Implemented Stream methods:
  virtual int Available();
  virtual bool IsOpen();

  // TODO: implement the missing Stream methods:
  virtual int Read(void *, uint32_t, unsigned long msTimeout = 0);
  virtual int Write(const void *, uint32_t, uint32_t msTimeout = 0);
  virtual void FlushInput();
  virtual void FlushOutput();
  virtual void FlushIO();

private:
  struct TxPacketInfo {
    PacketPtr pkt;
    uint32_t size;
    bool transmitting;
    double tt;
    uint32_t dst;
    TxPacketInfo() : transmitting(false) {}
  };
  typedef std::queue<TxPacketInfo> PacketQueue;
  typedef dccomms::Ptr<std::queue<TxPacketInfo>> PacketQueuePtr;
  std::mutex _txDataQueue_mutex;
  PacketQueuePtr _txQueues[10];
  void InitTxDataQueues();
  bool SendingData();
  void PrepareDataAndSend();
  void DiscardPacketsInRxFIFO();
  void SlaveRunRx();
  void MasterRunRx();
  void SlaveRunTx();
  void MasterRunTx();
  void MasterProcessRxPacket(const DcMacPacketPtr &pkt);
  void SlaveProcessRxPacket(const DcMacPacketPtr &pkt);
  PacketPtr WaitForNextRxPacket();
  PacketPtr WaitForNextTxPacket();
  PacketPtr GetLastTxPacket();
  PacketPtr PopLastTxPacket();
  void PushNewRxPacket(PacketPtr);
  void PushNewTxPacket(PacketPtr);
  unsigned int GetRxFifoSize();
  unsigned int GetTxFifoSize();
  void InitSlaveRtsReqs(bool reinitCtsCounter = false);

  struct SlaveRTS {
    bool req;
    uint16_t reqmillis, reqdatasize;
    uint16_t dst;
    uint32_t ctsBytes;
  };

  std::string _dccommsId;
  Mode _mode;
  Status _status;
  Ptr<DcMacPacketBuilder> _pb;
  PacketBuilderPtr _highPb;
  PacketPtr _flushPkt;
  uint16_t _addr, _maxSlaves, _maxNodes;
  DcMacRtsDataSizeField _time; // millis
  DcMacPacketPtr _txDataPacket;
  PacketPtr _txUpperPkt;

  std::mutex _rxfifo_mutex, _txfifo_mutex;
  std::condition_variable _rxfifo_cond, _txfifo_cond;
  std::queue<PacketPtr> _rxfifo, _txfifo;
  uint32_t _rxQueueSize, _txQueueSize;
  uint32_t _maxQueueSize;
  bool _sync, _started;
  std::thread _tx, _rx;
  std::mutex _status_mutex;
  std::condition_variable _status_cond;
  uint32_t _rtsCtsSlotDur;  // millis
  uint32_t _maxDataSlotDur; // millis
  uint32_t _currentRtsSlot;
  uint32_t _rtsDataTime;
  uint16_t _rtsDataSize;
  uint32_t _devBitRate;      // bps
  double _devIntrinsicDelay; // millis
  double _propSpeed;         // m/s
  double _maxDistance;       // m
  std::vector<SlaveRTS> _slaveRtsReqs;
  uint32_t _rtsSlave;
  uint8_t _ackMask;
  bool _ackReceived;
  bool _sendingDataPacket;
  uint32_t _sendingDataPacketSize;
  bool _replyAckPending;
  bool _waitingForAck;
  uint32_t _waitingForAckFrom;
  DcMacAckField _lastDataReceivedFrom;
};

} // namespace dccomms_examples

#endif // DCCOMMS_EXAMPLES_DCMAC_H
