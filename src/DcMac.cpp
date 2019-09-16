#include <class_loader/multi_library_class_loader.hpp>
#include <umci/DcMac.h>

namespace umci {

DcMacPacket::DcMacPacket() {
  _prefixSize = ADD_SIZE + FLAGS_SIZE;
  _overheadSize = PRE_SIZE + _prefixSize + FCS_SIZE;
  _maxPacketSize = _overheadSize + CTSRTS_FIELD_SIZE + PAYLOAD_SIZE_FIELD_SIZE +
                   MAX_PAYLOAD_SIZE;
  _AllocBuffer(_maxPacketSize);
  _Init();
}

PacketPtr DcMacPacket::Create() { return CreateObject<DcMacPacket>(); }

void DcMacPacket::_Init() {
  _pre = GetBuffer();
  *_pre = 0x55;
  _add = _pre + 1;
  _flags = _add + 1;
  _variableArea = _flags + 1;
  _masterAckMask = _variableArea;
  _slaveAckMask = _variableArea;
  _rtsSizeByte0 = _variableArea;
  _rtsSizeByte1 = _rtsSizeByte0 + 1;
  _payloadSize = _variableArea;
  _payload = _payloadSize + 1;
  _fcs = _payload + 0;
  _SetPayloadSizeField(0);
}

int DcMacPacket::GetPayloadSizeFromPacketSize(int size) {
  return size - DcMacPacket::PRE_SIZE - DcMacPacket::ADD_SIZE -
         DcMacPacket::FLAGS_SIZE - DcMacPacket::PAYLOAD_SIZE_FIELD_SIZE -
         DcMacPacket::FCS_SIZE;
}

inline int DcMacPacket::_GetTypeSize(Type ptype, uint8_t *buffer) {
  int size;
  if (ptype == Type::cts || ptype == Type::rts) {
    size = CTSRTS_FIELD_SIZE;
  } else if (ptype == data) {
    uint16_t payloadSize = _GetPayloadSizeFromBuffer(buffer);
    size = PAYLOAD_SIZE_FIELD_SIZE + payloadSize;
  } else if (ptype == sync) { // sync
    size = SYNC_FIELD_SIZE;
  }
  return size;
}

bool DcMacPacket::GetSlaveAck(uint8_t node) {
  return *_slaveAckMask & (0x08 << (node));
}
void DcMacPacket::SetSlaveAck(uint8_t node) {
  *_slaveAckMask = *_slaveAckMask | (0x08 << (node));
}

void DcMacPacket::SetSlaveAckMask(const DcMacAckField &mask) {
  *_slaveAckMask = *_slaveAckMask & 0x07;
  *_slaveAckMask = *_slaveAckMask | (mask << 3);
}

DcMacAckField DcMacPacket::GetSlaveAckMask() { return (*_slaveAckMask >> 3); }

void DcMacPacket::SetMasterAckMask(const DcMacAckField &mask) {
  *_masterAckMask = mask;
}

uint8_t DcMacPacket::GetMasterAckMask() { return *_masterAckMask; }

void DcMacPacket::DoCopyFromRawBuffer(void *buffer) {
  uint8_t *flags = (uint8_t *)buffer + PRE_SIZE + ADD_SIZE;
  Type ptype = _GetType(flags);
  int size = PRE_SIZE + _prefixSize + _GetTypeSize(ptype, flags) + FCS_SIZE;
  memcpy(GetBuffer(), buffer, size);
}

inline uint8_t *DcMacPacket::GetPayloadBuffer() { return _payload; }

inline uint32_t DcMacPacket::GetPayloadSize() {
  return _GetPayloadSizeFromBuffer(_flags);
}

inline uint16_t DcMacPacket::_GetPayloadSizeFromBuffer(uint8_t *buffer) {
  uint32_t value = 0;
  value = (value | *buffer & 0x70) << 4;
  value = value | *(buffer + 1);
  return value;
}

inline int DcMacPacket::GetPacketSize() {
  Type ptype = GetType();
  return _overheadSize + _GetTypeSize(ptype, _flags);
}

void DcMacPacket::Read(Stream *stream) {
  stream->WaitFor(_pre, PRE_SIZE);
  stream->Read(_add, ADD_SIZE);
  stream->Read(_flags, FLAGS_SIZE);
  Type type = _GetType(_flags);
  int size;
  uint8_t *end;
  if (type != unknown) {
    if (type == cts || type == rts) {
      stream->Read(_variableArea, CTSRTS_FIELD_SIZE);
      size = 0;
      end = _variableArea + CTSRTS_FIELD_SIZE;
    } else if (type == data) {
      stream->Read(_variableArea, PAYLOAD_SIZE_FIELD_SIZE);
      size = GetPayloadSize();
      end = _variableArea + PAYLOAD_SIZE_FIELD_SIZE;
    } else if (type == sync) { // sync (ack in)
      stream->Read(_variableArea, SYNC_FIELD_SIZE);
      size = 0;
      end = _variableArea + SYNC_FIELD_SIZE;
    }
  } else {
    size = 0;
    end = _variableArea;
  }

  if (type != unknown) {
    _fcs = end + size;
    stream->Read(end, size + FCS_SIZE);
  }
} // namespace dccomms_examples

inline void DcMacPacket::_SetPayloadSizeField(uint16_t payloadSize) {
  *_payloadSize = payloadSize & 0xff;
  *_flags = (*_flags & 0x8f) | ((payloadSize >> 4) & 0x70);
}

void DcMacPacket::PayloadUpdated(uint32_t payloadSize) {
  SetType(data);
  _SetPayloadSizeField(payloadSize);
  _fcs = _payload + payloadSize;
  UpdateFCS();
}

uint32_t DcMacPacket::SetPayload(uint8_t *data, uint32_t size) {
  SetType(Type::data);
  auto copySize = MAX_PAYLOAD_SIZE < size ? MAX_PAYLOAD_SIZE : size;
  _SetPayloadSizeField(copySize);
  memcpy(_payload, data, copySize);
  _fcs = _payload + copySize;
  return copySize;
}

void DcMacPacket::UpdateFCS() {
  uint16_t crc;
  Type type = GetType();
  if (type != unknown) {
    if (type == cts || type == rts) {
      crc = Checksum::crc16(_add, _prefixSize + CTSRTS_FIELD_SIZE);
      _fcs = _variableArea + CTSRTS_FIELD_SIZE;
    } else if (type == data) {
      auto psize = GetPayloadSize();
      crc =
          Checksum::crc16(_add, _prefixSize + PAYLOAD_SIZE_FIELD_SIZE + psize);
      _fcs = _variableArea + PAYLOAD_SIZE_FIELD_SIZE + psize;
    } else if (type == sync) { // sync
      crc = Checksum::crc16(_add, _prefixSize + SYNC_FIELD_SIZE);
      _fcs = _variableArea + SYNC_FIELD_SIZE;
    }
  } else {
    _fcs = _variableArea;
  }
  if (type != unknown) {
    *_fcs = (uint8_t)(crc >> 8);
    *(_fcs + 1) = (uint8_t)(crc & 0xff);
  }
}

bool DcMacPacket::_CheckFCS() {
  uint16_t crc;
  Type type = GetType();
  if (type != unknown) {
    if (type == cts || type == rts) {
      crc = Checksum::crc16(_add, _prefixSize + CTSRTS_FIELD_SIZE + FCS_SIZE);
    } else if (type == data) {
      crc = Checksum::crc16(_add, _prefixSize + PAYLOAD_SIZE_FIELD_SIZE +
                                      GetPayloadSize() + FCS_SIZE);
    } else if (type == sync) { // sync
      crc = Checksum::crc16(_add, _prefixSize + SYNC_FIELD_SIZE + FCS_SIZE);
    }
  } else {
    crc = 1;
  }
  return crc == 0;
}

bool DcMacPacket::PacketIsOk() { return _CheckFCS(); }

void DcMacPacket::SetDst(uint8_t add) {
  *_add = (*_add & 0xf0) | (add & 0xf);
  SetVirtualDestAddr(add);
}

uint8_t DcMacPacket::GetDst() { return *_add & 0xf; }

void DcMacPacket::_SetType(uint8_t *flags, Type type) {
  uint8_t ntype = static_cast<uint8_t>(type);
  *flags = (*flags & 0xf8) | (ntype & 0x7);
}

void DcMacPacket::SetType(Type type) { _SetType(_flags, type); }

DcMacPacket::Type DcMacPacket::_GetType(uint8_t *flags) {
  uint8_t ntype = (*flags & 0x7);
  Type value;
  if (ntype < 4)
    value = static_cast<Type>(ntype);
  else
    value = unknown;
  return value;
}

DcMacPacket::Type DcMacPacket::GetType() { return _GetType(_flags); }

void DcMacPacket::SetSrc(uint8_t add) {
  *_add = (*_add & 0xf) | ((add & 0xf) << 4);
  SetVirtualSrcAddr(add);
}

uint8_t DcMacPacket::GetSrc() { return (*_add & 0xf0) >> 4; }

DcMacRtsDataSizeField DcMacPacket::GetRtsDataSize() {
  Type type = GetType();
  if (type != data && type != unknown) {
    return _GetRtsDataSize();
  } else {
    return 0;
  }
}

uint16_t DcMacPacket::_GetRtsDataSize() {
  uint16_t v = (*_rtsSizeByte0 & 0x7) << 8 | *_rtsSizeByte1;
  return v * 2;
}

void DcMacPacket::SetRtsDataSize(const DcMacRtsDataSizeField &ds) {
  uint16_t half = std::ceil(ds / 2.);
  *_rtsSizeByte0 = *_rtsSizeByte0 & 0xf8;
  *_rtsSizeByte0 = *_rtsSizeByte0 | ((half & 0x700) >> 8);
  *_rtsSizeByte1 = half & 0xff;
}

CLASS_LOADER_REGISTER_CLASS(DcMacPacketBuilder, IPacketBuilder)

/***************************/
/*       END PACKET        */
/***************************/

DcMac::DcMac() : CommsDeviceService(CreateObject<DcMacPacketBuilder>()) {
  _maxQueueSize = UINT32_MAX;
  _txQueueSize = 0;
  _rxQueueSize = 0;
  _started = false;
  _pb = CreateObject<DcMacPacketBuilder>();
  _devIntrinsicDelay = 0;
  _devBitRate = 1e4;
  SetLogName("DcMac");
  LogToConsole(true);
  _txDataPacket = CreateObject<DcMacPacket>();
  _txDataPacket->SetType(DcMacPacket::data);
  _sendingDataPacket = false;
}

void DcMac::SetAddr(const uint16_t &addr) {
  _addr = addr;
  Log->debug("Addr: {}", _addr);
}

uint16_t DcMac::GetAddr() { return _addr; }

void DcMac::SetMode(const Mode &mode) {
  _mode = mode;
  Log->debug("Mode: {}", _mode);
}

void DcMac::SetNumberOfNodes(const uint16_t num) {
  _maxSlaves = num;
  _maxNodes = _maxSlaves + 1;
  _slaveRtsReqs.clear();
  for (int add = 0; add < _maxSlaves; add++) {
    SlaveRTS slaveRts;
    _slaveRtsReqs.push_back(slaveRts);
  }
  Log->debug("Max. nodes: {}", _maxSlaves);
}

void DcMac::SetPktBuilder(const PacketBuilderPtr &pb) { _highPb = pb; }

void DcMac::InitSlaveRtsReqs(bool reinitCtsCounter) {
  if (!reinitCtsCounter)
    for (SlaveRTS &data : _slaveRtsReqs) {
      data.req = false;
      data.reqmillis = 0;
    }
  else
    for (SlaveRTS &data : _slaveRtsReqs) {
      data.req = false;
      data.reqmillis = 0;
      data.ctsBytes = 0;
    }
}

DcMac::Mode DcMac::GetMode() {
  return _mode;
  Log->debug("Mode: {}", _mode);
}

void DcMac::SetDevBitRate(const uint32_t &bitrate) { _devBitRate = bitrate; }
void DcMac::SetDevIntrinsicDelay(const double &delay) {
  _devIntrinsicDelay = delay;
}

void DcMac::SetCommsDeviceId(std::string nspace) { _dccommsId = nspace; }
void DcMac::Start() {
  SetBlockingTransmission(false);
  CommsDeviceService::SetCommsDeviceId(_dccommsId);
  CommsDeviceService::Start();
  _time = RelativeTime::GetMillis();
  if (!_highPb)
    return;

  InitTxDataQueues();
  InitSlaveRtsReqs(true);
  DiscardPacketsInRxFIFO();
  if (_mode == master) {
    MasterRunRx();
    MasterRunTx();
  } else {
    SlaveRunRx();
    SlaveRunTx();
  }
  _started = true;
  _currentRtsSlot = 0;
}

void DcMac::SetMaxDataSlotDur(const uint32_t &slotdur) {
  _maxDataSlotDur = slotdur;
}

void DcMac::SetRtsSlotDur(const uint32_t &slotdur) { _rtsCtsSlotDur = slotdur; }
void DcMac::ReadPacket(const PacketPtr &pkt) {
  PacketPtr npkt = WaitForNextRxPacket();
  pkt->CopyFromRawBuffer(npkt->GetBuffer());
}

void DcMac::WritePacket(const PacketPtr &pkt) { PushNewTxPacket(pkt); }

void DcMac::DiscardPacketsInRxFIFO() {
  if (!_flushPkt)
    _flushPkt = _pb->Create();
  while (GetRxFifoSize() > 0) {
    CommsDeviceService::ReadPacket(_flushPkt);
  }
}

PacketPtr DcMac::WaitForNextRxPacket() {
  std::unique_lock<std::mutex> lock(_rxfifo_mutex);
  while (_rxfifo.empty()) {
    _rxfifo_cond.wait(lock);
  }
  PacketPtr dlf = _rxfifo.front();
  auto size = dlf->GetPacketSize();
  _rxfifo.pop();
  _rxQueueSize -= size;
  return dlf;
}

PacketPtr DcMac::WaitForNextTxPacket() {
  std::unique_lock<std::mutex> lock(_txfifo_mutex);
  while (_txfifo.empty()) {
    _txfifo_cond.wait(lock);
  }
  PacketPtr dlf = _txfifo.front();
  auto size = dlf->GetPacketSize();
  _txfifo.pop();
  _txQueueSize -= size;
  return dlf;
}

PacketPtr DcMac::GetLastTxPacket() {
  std::unique_lock<std::mutex> lock(_txfifo_mutex);
  PacketPtr dlf;
  if (!_txfifo.empty())
    dlf = _txfifo.front();
  return dlf;
}

PacketPtr DcMac::PopLastTxPacket() {
  std::unique_lock<std::mutex> lock(_txfifo_mutex);
  PacketPtr dlf;
  if (!_txfifo.empty()) {
    dlf = _txfifo.front();
    auto size = dlf->GetPacketSize();
    Log->debug("Tx packet POP. Seq: {}", dlf->GetSeq());
    _txQueueSize -= size;
    _txfifo.pop();
  }
  return dlf;
}

void DcMac::PushNewRxPacket(PacketPtr dlf) {
  _rxfifo_mutex.lock();
  auto size = dlf->GetPacketSize();
  if (size + _rxQueueSize <= _maxQueueSize) {
    _rxQueueSize += size;
    _rxfifo.push(dlf);
  } else {
    Log->warn("Rx queue full. Packet dropped");
  }
  _rxfifo_cond.notify_one();
  _rxfifo_mutex.unlock();
}

void DcMac::PushNewTxPacket(PacketPtr pkt) {
  PacketPtr dlf = pkt->CreateCopy();
  _txfifo_mutex.lock();
  auto size = dlf->GetPacketSize();
  if (size + _txQueueSize <= _maxQueueSize) {
    _txQueueSize += size;
    _txfifo.push(dlf);
    Log->debug("Tx packet added. Seq: {}", dlf->GetSeq());
  } else {
    Log->warn("Tx queue full. Packet dropped");
  }
  _txfifo_cond.notify_one();
  _txfifo_mutex.unlock();
  Log->debug("Tx fifo size: {} ({} packets)", _txQueueSize, _txfifo.size());
}

double DcMac::GetPktTransmissionMillis(const uint32_t &size) {
  return (size * 8. / _devBitRate) * 1000 + _devIntrinsicDelay;
}

void DcMac::SetPropSpeed(const double &propspeed) {
  _propSpeed = propspeed; // m/s
}

void DcMac::SetMaxDistance(const double &distance) {
  _maxDistance = distance; // m
}

void DcMac::UpdateSlotDurFromEstimation() {
  DcMacPacket pkt;
  pkt.SetType(DcMacPacket::rts);
  auto size = pkt.GetPacketSize();
  auto tt = GetPktTransmissionMillis(size);
  auto maxPropDelay = _maxDistance / _propSpeed * 1000; // ms
  auto error = 45;
  auto slotdur = (tt + maxPropDelay) + error;
  Log->debug(
      "RTS/CTS size: {} ; TT: {} ms ; MP: {} ms ; Err: +{} ms ; ESD: {} ms",
      size, tt, maxPropDelay, error, slotdur);
  _rtsCtsSlotDur = slotdur;
}

void DcMac::SlaveRunTx() {
  /*
   * Este proceso se encarga de enviar los paquetes
   */
  _tx = std::thread([this]() {
    auto rtsSlotDelay = milliseconds((_addr - 1) * _rtsCtsSlotDur);
    auto ctsSlotDelay = milliseconds(_maxSlaves * _rtsCtsSlotDur);
    bool dataSentToSlave;
    DiscardPacketsInRxFIFO();
    while (1) {
      std::unique_lock<std::mutex> lock(_status_mutex);
      while (_status != syncreceived) {
        _status_cond.wait(lock);
      }
      auto now = std::chrono::system_clock::now();
      Log->debug("TX: SYNC RX!");
      _status = waitack;
      lock.unlock();
      if (_sendingDataPacket && _txDataPacket->GetDestAddr() == 0) {
        _waitingForAck = false;
        if (_ackMask & (1 << (_addr))) {
          Log->debug("MASTER DATA SUCCESS");
          _sendingDataPacket = false;
        } else {
          Log->warn("MASTER DATA LOST");
        }
      }

      Log->debug("Start iteration for sending packet");

      auto rtsWakeUp = now + rtsSlotDelay;
      auto ctsWakeUp = now + ctsSlotDelay;

      cv_status waitres = cv_status::no_timeout;
      if (_sendingDataPacket && dataSentToSlave &&
          _txDataPacket->GetDestAddr() < _addr) {
        _waitingForAck = false;
        Log->debug("Waiting for RTS with ACK 1");
        std::unique_lock<std::mutex> waitackLock(_status_mutex);
        while (_status != ackreceived && waitres == cv_status::no_timeout) {
          waitres = _status_cond.wait_until(waitackLock, rtsWakeUp);
        }
        if (_status == ackreceived) {
          Log->debug("SLAVE DATA SUCCESS 1");
          _sendingDataPacket = false;
          dataSentToSlave = false;
        } else {
          Log->warn("SLAVE DATA LOST 1");
        }
      }
      DcMacPacketPtr pkt(new DcMacPacket());
      bool sendRtsOrAck = false, sendRts = false;

      if (_replyAckPending) {
        pkt->SetRtsDataSize(0);
        pkt->SetSlaveAckMask(_lastDataReceivedFrom);
        _lastDataReceivedFrom = 0;
        sendRtsOrAck = true;
      }

      if (_sendingDataPacket) {
        if (!_waitingForAck) {
          auto dst = _txDataPacket->GetDestAddr();
          pkt->SetDst(dst);
          pkt->SetRtsDataSize(_sendingDataPacketSize);
          sendRtsOrAck = true;
          sendRts = true;
        }
      } else {
        Log->debug("Check data in tx buffer");
        _txUpperPkt = GetLastTxPacket();
        if (_txUpperPkt) {
          PopLastTxPacket();
          Log->debug("Data in tx buffer. Seq: {}", _txUpperPkt->GetSeq());
          _sendingDataPacketSize = _txUpperPkt->GetPacketSize();
          auto dst = _txUpperPkt->GetDestAddr();
          _txDataPacket->SetDestAddr(dst);
          _txDataPacket->SetSrcAddr(_addr);
          _txDataPacket->SetPayload(_txUpperPkt->GetBuffer(),
                                    _sendingDataPacketSize);
          _txDataPacket->SetSeq(_txUpperPkt->GetSeq());
          _txDataPacket->UpdateFCS();
          _sendingDataPacket = true;
          _waitingForAck = false;
          Log->debug("Data packet for transmitting");

          pkt->SetDst(dst);
          pkt->SetRtsDataSize(_sendingDataPacketSize);
          sendRtsOrAck = true;
          sendRts = true;
        }
      }

      pkt->SetSrc(_addr);
      pkt->SetType(DcMacPacket::rts);

      pkt->UpdateFCS();

      if (waitres == cv_status::no_timeout) {
        Log->debug("Sleep until RTS slot");
        this_thread::sleep_until(rtsWakeUp);
      } else {
        Log->debug("Do not sleep for RTS slot");
      }

      if (sendRtsOrAck) {
        CommsDeviceService::WritePacket(pkt);
        if (sendRts) {
          Log->debug("Send RTS");
        }
        if (_replyAckPending) {
          Log->debug("Send ACK");
          _replyAckPending = false;
        }
      }

      waitres = cv_status::no_timeout;
      if (_sendingDataPacket && dataSentToSlave &&
          _txDataPacket->GetDestAddr() > _addr) {
        _waitingForAck = false;
        Log->debug("Waiting for RTS with ACK 2");
        std::unique_lock<std::mutex> waitackLock(_status_mutex);
        while (_status != ackreceived && waitres == cv_status::no_timeout) {
          waitres = _status_cond.wait_until(waitackLock, ctsWakeUp);
        }
        if (_status == ackreceived) {
          Log->debug("SLAVE DATA SUCCESS 2");
          _sendingDataPacket = false;
          dataSentToSlave = false;
        } else {
          Log->warn("SLAVE DATA LOST 2");
        }
      }

      if (!_sendingDataPacket) {
        Log->debug("No data to send in this cycle");
        continue;
      } else {
        Log->debug("DATA to send");
      }

      if (waitres == cv_status::no_timeout)
        this_thread::sleep_until(ctsWakeUp);

      if (sendRts) {
        Log->debug("WAIT CTS");
      }

      std::unique_lock<std::mutex> statusLock(_status_mutex);
      while (_status != syncreceived && _status != ctsreceived) {
        _status_cond.wait(statusLock);
      }
      if (_status == ctsreceived) {
        if (_txDataPacket->PacketIsOk()) {
          CommsDeviceService::WritePacket(_txDataPacket);
          Log->debug("SEND DATA. Seq {} ; Size {}", _txDataPacket->GetSeq(),
                     _sendingDataPacketSize);
          if (_txDataPacket->GetDestAddr() != 0)
            dataSentToSlave = true;
          else
            dataSentToSlave = false;
          _waitingForAck = true;
        } else {
          Log->critical("data packet corrupt before transmitting");
        }
      }
    }
  });

  _tx.detach();
} // namespace dccomms_examples

void DcMac::SlaveRunRx() {
  /*
   * Este proceso se encarga de recibir los paquetes
   */
  _rx = std::thread([this]() {
    uint32_t npkts = 0;
    DiscardPacketsInRxFIFO();
    DcMacPacketPtr pkt = CreateObject<DcMacPacket>();
    while (1) {
      CommsDeviceService::ReadPacket(pkt);
      if (pkt->PacketIsOk()) {
        npkts += 1;
        Log->debug("S: RX DCMAC PKT {} bytes; {}", pkt->GetPacketSize(),
                   pkt->GetType());
        SlaveProcessRxPacket(pkt);
      } else {
        Log->warn("Errors on packet");
      }
    }
  });
  _rx.detach();
}
bool DcMac::SendingData() {
  for (int i = 0; i < _maxNodes; i++) {
    if (!_txQueues[i]->empty())
      return true;
  }
  return false;
}

void DcMac::PrepareDataAndSend() {
  Log->debug("Check data in tx buffer");
  std::unique_lock<std::mutex> lock(_txDataQueue_mutex);
  TxPacketInfo pktInfo;
  while (_txUpperPkt = GetLastTxPacket()) {
    PopLastTxPacket();
    Log->debug("Data in tx buffer. Seq: {}", _txUpperPkt->GetSeq());
    auto size = _txUpperPkt->GetPacketSize();
    auto dstAddr = _txUpperPkt->GetDestAddr();
    auto dataPkt = CreateObject<DcMacPacket>();
    dataPkt->SetType(DcMacPacket::data);
    dataPkt->SetDestAddr(dstAddr);
    dataPkt->SetSrcAddr(_addr);
    dataPkt->SetPayload(_txUpperPkt->GetBuffer(), size);
    dataPkt->SetSeq(_txUpperPkt->GetSeq());
    dataPkt->UpdateFCS();
    Log->debug("({}) Prepare data packet to {}", _addr, dstAddr);
    pktInfo.pkt = dataPkt;
    pktInfo.size = size;
    pktInfo.tt = GetPktTransmissionMillis(dataPkt->GetPacketSize());
    pktInfo.dst = dstAddr;
    pktInfo.transmitting = false;
    _txQueues[dstAddr]->push(pktInfo);
  }
  TxPacketInfo *pkt;
  for (int i = 0; i < _maxNodes; i++) {
    PacketQueuePtr pktQueue = _txQueues[i];
    if (!pktQueue->empty() && (pkt = &pktQueue->front())) {
      CommsDeviceService::WritePacket(pkt->pkt);
      Log->debug("SEND DATA FROM {} to {} ; Seq {} ; Size {}", _addr, pkt->dst,
                 pkt->pkt->GetSeq(), pkt->size);
      pkt->transmitting = true;
      this_thread::sleep_for(
          milliseconds(static_cast<int>(std::round(pkt->tt))));
    }
  }
}
void DcMac::InitTxDataQueues() {
  for (int i = 0; i < _maxNodes; i++) {
    _txQueues[i] = dccomms::CreateObject<PacketQueue>();
  }
}

void DcMac::MasterRunTx() {
  /*
   * Este proceso se encarga de enviar los paquetes
   */
  _tx = std::thread([this]() {
    PacketPtr pkt = 0;
    while (1) {
      Log->debug("iteration start");
      if (_rxfifo.size() > 0) {
        Log->warn("RX fifo not empty at the beginning of the iteration. "
                  "Discard packets...");
        DiscardPacketsInRxFIFO();
      }
      RelativeTime::Reset();
      _time = RelativeTime::GetMillis();
      _currentRtsSlot = 0;
      Log->debug("Send sync signal. Slot: {} ; time: {}", _currentRtsSlot,
                 _time);

      DcMacPacketPtr syncPkt(new DcMacPacket());
      syncPkt->SetDst(0xf);
      syncPkt->SetSrc(_addr);
      syncPkt->SetType(DcMacPacket::sync);
      syncPkt->SetMasterAckMask(_ackMask);
      syncPkt->UpdateFCS();
      if (syncPkt->PacketIsOk()) {
        CommsDeviceService::WritePacket(syncPkt);
      } else {
        Log->critical("Internal error. packet has errors");
      }

      auto pktSize = syncPkt->GetPacketSize();
      uint32_t minEnd2End =
          ((pktSize * 8) / _devBitRate) * 1000 + _devIntrinsicDelay;
      this_thread::sleep_for(milliseconds(minEnd2End));

      InitSlaveRtsReqs();
      for (int s = 0; s < _maxSlaves; s++) {
        bool slotEnd = false;
        _currentRtsSlot += 1;
        _status = waitrts;
        auto wakeuptime =
            std::chrono::system_clock::now() + milliseconds(_rtsCtsSlotDur);

        while (!slotEnd) {
          std::unique_lock<std::mutex> statusLock(_status_mutex);

          auto res = _status_cond.wait_until(statusLock, wakeuptime);
          if (res == std::cv_status::no_timeout && _status == rtsreceived) {
            if (_rtsSlave == _currentRtsSlot) {
              Log->debug("RTS received from slave {}", _currentRtsSlot);
            } else {
              Log->warn("RTS received from wrong slave");
            }
          } else if (res == std::cv_status::timeout) {
            _time = RelativeTime::GetMillis();
            if (_status != rtsreceived)
              Log->warn(
                  "Timeout waiting for rts packet from slave {}. Time: {}",
                  _currentRtsSlot, _time);
            slotEnd = true;
          }
        }
      }
      bool req = true;
      _ackMask = 0;
      while (req) {
        SlaveRTS *winnerSlave = 0;
        uint32_t ctsBytes = UINT32_MAX;
        uint16_t slaveAddr;
        req = false;
        for (int i = 0; i < _maxSlaves; i++) {
          SlaveRTS *data = &_slaveRtsReqs[i];
          if (data->req) {
            req = true;
            if (ctsBytes > data->ctsBytes) {
              ctsBytes = data->ctsBytes;
              winnerSlave = data;
              slaveAddr = i + 1;
            }
          }
        }
        if (winnerSlave) {
          _status = DcMac::waitdata; // Should be set in mutex context
          winnerSlave->req = false;
          DcMacPacketPtr ctsPkt(new DcMacPacket());
          ctsPkt->SetDst(slaveAddr);
          ctsPkt->SetSrc(_addr);
          ctsPkt->SetType(DcMacPacket::cts);
          ctsPkt->SetRtsDataSize(winnerSlave->reqdatasize);
          ctsPkt->UpdateFCS();
          winnerSlave->ctsBytes += winnerSlave->reqdatasize;
          if (ctsPkt->PacketIsOk()) {
            Log->debug("Send CTS to {}", slaveAddr);
            CommsDeviceService::WritePacket(ctsPkt);
            auto wakeuptime =
                std::chrono::system_clock::now() +
                milliseconds(static_cast<int>(
                    std::ceil(_rtsCtsSlotDur + winnerSlave->reqmillis * 1)));
            bool slotEnd = false;
            while (_status != datareceived && !slotEnd) {
              std::unique_lock<std::mutex> statusLock(_status_mutex);
              auto res = _status_cond.wait_until(statusLock, wakeuptime);
              if (res == std::cv_status::no_timeout &&
                  _status == datareceived) {
                Log->debug("Data detected from slave {}", slaveAddr);
                if (winnerSlave->dst == 0)
                  _ackMask |= (1 << (slaveAddr));
              } else if (res == std::cv_status::timeout) {
                _time = RelativeTime::GetMillis();
                if (_status != datareceived && winnerSlave->dst == _addr)
                  Log->warn("Timeout waiting for data packet from slave {}. "
                            "Time: {}",
                            slaveAddr, _time);
                slotEnd = true;
              }
            }

          } else {
            Log->critical("Internal error. packet has errors");
          }
        }
      }
      PrepareDataAndSend();
      this_thread::sleep_for(milliseconds(10));
    }
  });
  _tx.detach();
}

void DcMac::MasterRunRx() {
  /*
   * Este proceso se encarga de recibir los paquetes
   */
  _rx = std::thread([this]() {
    uint32_t npkts = 0;
    DiscardPacketsInRxFIFO();
    DcMacPacketPtr pkt = CreateObject<DcMacPacket>();
    while (1) {
      CommsDeviceService::ReadPacket(pkt);
      if (pkt->PacketIsOk()) {
        npkts += 1;
        Log->debug("M: RX DCMAC PKT {} bytes; {}", pkt->GetPacketSize(),
                   pkt->GetType());
        MasterProcessRxPacket(pkt);
      } else {
        Log->warn("Errors on packet");
      }
    }
  });
  _rx.detach();
}

void DcMac::MasterProcessRxPacket(const DcMacPacketPtr &pkt) {
  std::unique_lock<std::mutex> lock(_status_mutex);
  DcMacPacket::Type type = pkt->GetType();
  auto dst = pkt->GetDst();
  auto src = pkt->GetSrc();

  switch (type) {
  case DcMacPacket::sync: {
    Log->warn("SYNC detected");
    break;
  }
  case DcMacPacket::cts: {
    Log->warn("CTS detected from {}", src);
    break;
  }
  case DcMacPacket::rts: {
    if (pkt->GetSlaveAckMask()) {
      if (pkt->GetSlaveAck(_addr)) {
        std::unique_lock<std::mutex> lock(_txDataQueue_mutex);
        Log->debug("ACK received from {}", src);
        PacketQueuePtr pktQueue = _txQueues[src];
        if (!pktQueue->empty()) {
          pktQueue->pop();
        } else {
          Log->critical("Internal error: unexpected ACK received from {}", src);
        }
      } else {
        Log->debug("ACK detected from {}", src);
      }
    }
    _rtsDataSize = pkt->GetRtsDataSize();
    if (_rtsDataSize > 0) {
      _status = rtsreceived;
      _rtsDataTime = GetPktTransmissionMillis(_rtsDataSize);
      _rtsSlave = pkt->GetSrcAddr();
      SlaveRTS *rts = &_slaveRtsReqs[_rtsSlave - 1];
      rts->req = true;
      rts->reqmillis = _rtsDataTime;
      rts->reqdatasize = _rtsDataSize;
      rts->dst = dst;
      Log->debug("{} RTS received. {} ms ; {} B ; From: {}",
                 RelativeTime::GetMillis(), _rtsDataTime, _rtsDataSize,
                 pkt->GetSrc());
    }
    break;
  }
  case DcMacPacket::data: {
    _status = datareceived;
    if (dst == _addr) {
      Log->debug("({}) DATA received from {} (Seq: {})", _addr, pkt->GetSrc(),
                 pkt->GetSeq());
      auto npkt = _highPb->Create();
      uint8_t *payload = pkt->GetPayloadBuffer();
      npkt->DoCopyFromRawBuffer(payload);
      npkt->SetVirtualSeq(pkt->GetSeq());
      npkt->SetVirtualDestAddr(pkt->GetDestAddr());
      npkt->SetVirtualSrcAddr(pkt->GetSrcAddr());
      if (!npkt->PacketIsOk()) {
        Log->critical("Data packet corrupted from {} (Seq: {})",
                      npkt->GetSrcAddr(), npkt->GetSeq());
      }
      auto src = pkt->GetSrc();
      _lastDataReceivedFrom = (_lastDataReceivedFrom | (1 << (src)));
      _replyAckPending = true;
      PushNewRxPacket(npkt);
    } else {
      Log->debug("DATA detected from {}", pkt->GetSrc());
    }
    break;
  }
  }
  _status_cond.notify_all();
}
void DcMac::SlaveProcessRxPacket(const DcMacPacketPtr &pkt) {
  std::unique_lock<std::mutex> lock(_status_mutex);
  DcMacPacket::Type type = pkt->GetType();
  auto dst = pkt->GetDst();

  switch (type) {
  case DcMacPacket::sync: {
    RelativeTime::Reset();
    _ackMask = pkt->GetMasterAckMask();
    _status = DcMac::syncreceived;
    Log->debug("SYNC received");
    break;
  }
  case DcMacPacket::cts: {
    _rtsDataTime = pkt->GetRtsDataSize();
    if (dst == _addr) {
      Log->debug("CTS received from {}", pkt->GetSrc());
      _status = DcMac::ctsreceived;
    } else {
      Log->debug("CTS detected from {}", pkt->GetSrc());
      _status = DcMac::waitcts;
    }
    break;
  }
  case DcMacPacket::rts: {
    if (pkt->GetSlaveAck(_addr)) {
      Log->debug("ACK received from {}", pkt->GetSrc());
      _status = ackreceived;
    }

    break;
  }
  case DcMacPacket::data: {
    _status = datareceived;
    if (dst == _addr) {
      Log->debug("({}) DATA received from {} (Seq: {})", _addr, pkt->GetSrc(),
                 pkt->GetSeq());
      auto npkt = _highPb->Create();
      uint8_t *payload = pkt->GetPayloadBuffer();
      npkt->DoCopyFromRawBuffer(payload);
      npkt->SetVirtualSeq(pkt->GetSeq());
      npkt->SetVirtualDestAddr(pkt->GetDestAddr());
      npkt->SetVirtualSrcAddr(pkt->GetSrcAddr());
      if (!npkt->PacketIsOk()) {
        Log->critical("Data packet corrupted from {} (Seq: {})",
                      npkt->GetSrcAddr(), npkt->GetSeq());
      }
      auto src = pkt->GetSrc();
      _lastDataReceivedFrom = (_lastDataReceivedFrom | (1 << (src)));
      _replyAckPending = true;
      PushNewRxPacket(npkt);
    } else {
      Log->debug("DATA detected from {}", pkt->GetSrc());
    }
    break;
  }
  }
  _status_cond.notify_all();
}

int DcMac::Available() {
  // TODO: return the payload bytes in the rx fifo instead
  return GetRxFifoSize();
}
unsigned int DcMac::GetRxFifoSize() {
  unsigned int size;
  _rxfifo_mutex.lock();
  size = _rxQueueSize;
  _rxfifo_mutex.unlock();
  return size;
}

unsigned int DcMac::GetTxFifoSize() {
  unsigned int size;
  _txfifo_mutex.lock();
  size = _txQueueSize;
  _txfifo_mutex.unlock();
  return size;
}

bool DcMac::IsOpen() { return _started; }

int DcMac::Read(void *, uint32_t, unsigned long msTimeout) {
  throw CommsException("int CommsDeviceService::Read() Not implemented",
                       COMMS_EXCEPTION_NOTIMPLEMENTED);
}
int DcMac::Write(const void *, uint32_t, uint32_t msTimeout) {
  throw CommsException("int CommsDeviceService::Write() Not implemented",
                       COMMS_EXCEPTION_NOTIMPLEMENTED);
}

void DcMac::FlushInput() {
  throw CommsException("void CommsDeviceService::FlushInput() Not implemented",
                       COMMS_EXCEPTION_NOTIMPLEMENTED);
}
void DcMac::FlushOutput() {
  throw CommsException("void CommsDeviceService::FlushOutput() Not implemented",
                       COMMS_EXCEPTION_NOTIMPLEMENTED);
}
void DcMac::FlushIO() {
  throw CommsException("void CommsDeviceService::FlushIO() Not implemented",
                       COMMS_EXCEPTION_NOTIMPLEMENTED);
}
} // namespace umci
