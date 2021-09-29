//+build linux

/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

// Package ethtool  aims to provide a library giving a simple access to the
// Linux SIOCETHTOOL ioctl operations. It can be used to retrieve informations
// from a network device like statistics, driver related informations or
// even the peer of a VETH interface.
package ethtool

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Maximum size of an interface name
const (
	IFNAMSIZ = 16
)

// ioctl ethtool request
const (
	SIOCETHTOOL = 0x8946
)

// ethtool stats related constants.
const (
	ETH_GSTRING_LEN  = 32
	ETH_SS_STATS     = 1
	ETH_SS_FEATURES  = 4
	ETHTOOL_GDRVINFO = 0x00000003
	ETHTOOL_GSTRINGS = 0x0000001b
	ETHTOOL_GSTATS   = 0x0000001d
	// other CMDs from ethtool-copy.h of ethtool-3.5 package
	ETHTOOL_GSET      = 0x00000001 /* Get settings. */
	ETHTOOL_SSET      = 0x00000002 /* Set settings. */
	ETHTOOL_GMSGLVL   = 0x00000007 /* Get driver message level */
	ETHTOOL_SMSGLVL   = 0x00000008 /* Set driver msg level. */
	ETHTOOL_GCHANNELS = 0x0000003c /* Get no of channels */
	ETHTOOL_SCHANNELS = 0x0000003d /* Set no of channels */
	ETHTOOL_GCOALESCE = 0x0000000e /* Get coalesce config */
	/* Get link status for host, i.e. whether the interface *and* the
	 * physical port (if there is one) are up (ethtool_value). */
	ETHTOOL_GLINK = 0x0000000a
	// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/ethtool.h#L1535
	ETHTOOL_GET_TS_INFO   = 0x00000041 /* Get timestamp support info */
	ETHTOOL_GMODULEINFO   = 0x00000042 /* Get plug-in module information */
	ETHTOOL_GMODULEEEPROM = 0x00000043 /* Get plug-in module eeprom */
	ETHTOOL_GPERMADDR     = 0x00000020
	ETHTOOL_GFEATURES     = 0x0000003a /* Get device offload settings */
	ETHTOOL_SFEATURES     = 0x0000003b /* Change device offload settings */
	ETHTOOL_GFLAGS        = 0x00000025 /* Get flags bitmap(ethtool_value) */
	ETHTOOL_GSSET_INFO    = 0x00000037 /* Get string set info */
)

// MAX_GSTRINGS maximum number of stats entries that ethtool can
// retrieve currently.
const (
	MAX_GSTRINGS       = 16384
	MAX_FEATURE_BLOCKS = (MAX_GSTRINGS + 32 - 1) / 32
	EEPROM_LEN         = 640
	PERMADDR_LEN       = 32
)

const ()

type ifreq struct {
	ifr_name [IFNAMSIZ]byte
	ifr_data uintptr
}

// following structures comes from uapi/linux/ethtool.h
type ethtoolSsetInfo struct {
	cmd       uint32
	reserved  uint32
	sset_mask uint32
	data      uintptr
}

type ethtoolGetFeaturesBlock struct {
	available     uint32
	requested     uint32
	active        uint32
	never_changed uint32
}

type ethtoolGfeatures struct {
	cmd    uint32
	size   uint32
	blocks [MAX_FEATURE_BLOCKS]ethtoolGetFeaturesBlock
}

type ethtoolSetFeaturesBlock struct {
	valid     uint32
	requested uint32
}

type ethtoolSfeatures struct {
	cmd    uint32
	size   uint32
	blocks [MAX_FEATURE_BLOCKS]ethtoolSetFeaturesBlock
}

type ethtoolDrvInfo struct {
	cmd          uint32
	driver       [32]byte
	version      [32]byte
	fw_version   [32]byte
	bus_info     [32]byte
	erom_version [32]byte
	reserved2    [12]byte
	n_priv_flags uint32
	n_stats      uint32
	testinfo_len uint32
	eedump_len   uint32
	regdump_len  uint32
}

// DrvInfo contains driver information
// ethtool.h v3.5: struct ethtool_drvinfo
type DrvInfo struct {
	Cmd         uint32
	Driver      string
	Version     string
	FwVersion   string
	BusInfo     string
	EromVersion string
	Reserved2   string
	NPrivFlags  uint32
	NStats      uint32
	TestInfoLen uint32
	EedumpLen   uint32
	RegdumpLen  uint32
}

// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/ethtool.h#L1334
type ethtoolTsInfo struct {
	cmd            uint32
	soTimestamping uint32
	phcIndex       int32
	txTypes        uint32
	txReserved     uint32
	rxFilters      uint32
	rxReserved     uint32
}

// TsInfo contains timestamp information
type TsInfo struct {
	Cmd            uint32
	SoTimestamping map[string]uint
	PhcIndex       int32
	TxTypes        map[string]uint32
	TxReserved     uint32
	RxFilters      map[string]uint32
	RxReserved     uint32
}

// Channels contains the number of channels for a given interface.
type Channels struct {
	Cmd           uint32
	MaxRx         uint32
	MaxTx         uint32
	MaxOther      uint32
	MaxCombined   uint32
	RxCount       uint32
	TxCount       uint32
	OtherCount    uint32
	CombinedCount uint32
}

// Coalesce is a coalesce config for an interface
type Coalesce struct {
	Cmd                      uint32
	RxCoalesceUsecs          uint32
	RxMaxCoalescedFrames     uint32
	RxCoalesceUsecsIrq       uint32
	RxMaxCoalescedFramesIrq  uint32
	TxCoalesceUsecs          uint32
	TxMaxCoalescedFrames     uint32
	TxCoalesceUsecsIrq       uint32
	TxMaxCoalescedFramesIrq  uint32
	StatsBlockCoalesceUsecs  uint32
	UseAdaptiveRxCoalesce    uint32
	UseAdaptiveTxCoalesce    uint32
	PktRateLow               uint32
	RxCoalesceUsecsLow       uint32
	RxMaxCoalescedFramesLow  uint32
	TxCoalesceUsecsLow       uint32
	TxMaxCoalescedFramesLow  uint32
	PktRateHigh              uint32
	RxCoalesceUsecsHigh      uint32
	RxMaxCoalescedFramesHigh uint32
	TxCoalesceUsecsHigh      uint32
	TxMaxCoalescedFramesHigh uint32
	RateSampleInterval       uint32
}

type ethtoolGStrings struct {
	cmd        uint32
	string_set uint32
	len        uint32
	data       [MAX_GSTRINGS * ETH_GSTRING_LEN]byte
}

type ethtoolStats struct {
	cmd     uint32
	n_stats uint32
	data    [MAX_GSTRINGS]uint64
}

type ethtoolEeprom struct {
	cmd    uint32
	magic  uint32
	offset uint32
	len    uint32
	data   [EEPROM_LEN]byte
}

type ethtoolModInfo struct {
	cmd        uint32
	tpe        uint32
	eeprom_len uint32
	reserved   [8]uint32
}

type ethtoolLink struct {
	cmd  uint32
	data uint32
}

type ethtoolPermAddr struct {
	cmd  uint32
	size uint32
	data [PERMADDR_LEN]byte
}

type Ethtool struct {
	fd int
}

// DriverName returns the driver name of the given interface name.
func (e *Ethtool) DriverName(intf string) (string, error) {
	info, err := e.getDriverInfo(intf)
	if err != nil {
		return "", err
	}
	return string(bytes.Trim(info.driver[:], "\x00")), nil
}

// BusInfo returns the bus information of the given interface name.
func (e *Ethtool) BusInfo(intf string) (string, error) {
	info, err := e.getDriverInfo(intf)
	if err != nil {
		return "", err
	}
	return string(bytes.Trim(info.bus_info[:], "\x00")), nil
}

// TimestampInfo returns the timstamp support information of the given interface name.
func (e *Ethtool) TimestampInfo(intf string) (TsInfo, error) {
	info, err := e.getTimestampInfo(intf)
	if err != nil {
		return TsInfo{}, err
	}

	// https://pkg.go.dev/golang.org/x/sys/unix#SOF_TIMESTAMPING_TX_HARDWARE
	supportedTsModes := map[uint]string{
		unix.SOF_TIMESTAMPING_TX_HARDWARE:  "SOF_TIMESTAMPING_TX_HARDWARE",
		unix.SOF_TIMESTAMPING_TX_SOFTWARE:  "SOF_TIMESTAMPING_TX_SOFTWARE",
		unix.SOF_TIMESTAMPING_RX_HARDWARE:  "SOF_TIMESTAMPING_RX_HARDWARE",
		unix.SOF_TIMESTAMPING_RX_SOFTWARE:  "SOF_TIMESTAMPING_RX_SOFTWARE",
		unix.SOF_TIMESTAMPING_SOFTWARE:     "SOF_TIMESTAMPING_SOFTWARE",
		unix.SOF_TIMESTAMPING_SYS_HARDWARE: "SOF_TIMESTAMPING_SYS_HARDWARE",
		unix.SOF_TIMESTAMPING_RAW_HARDWARE: "SOF_TIMESTAMPING_RAW_HARDWARE",
		unix.SOF_TIMESTAMPING_OPT_ID:       "SOF_TIMESTAMPING_OPT_ID",
		unix.SOF_TIMESTAMPING_TX_SCHED:     "SOF_TIMESTAMPING_TX_SCHED",
		unix.SOF_TIMESTAMPING_TX_ACK:       "SOF_TIMESTAMPING_TX_ACK",
		unix.SOF_TIMESTAMPING_OPT_CMSG:     "SOF_TIMESTAMPING_OPT_CMSG",
		unix.SOF_TIMESTAMPING_OPT_TSONLY:   "SOF_TIMESTAMPING_OPT_TSONLY",
		unix.SOF_TIMESTAMPING_OPT_STATS:    "SOF_TIMESTAMPING_OPT_STATS",
		unix.SOF_TIMESTAMPING_OPT_PKTINFO:  "SOF_TIMESTAMPING_OPT_PKTINFO",
		unix.SOF_TIMESTAMPING_OPT_TX_SWHW:  "SOF_TIMESTAMPING_OPT_TX_SWHW",
	}

	var soTimestamping = make(map[string]uint)

	// https://kernel.googlesource.com/pub/scm/network/ethtool/ethtool/+/refs/tags/v5.14/ethtool.c#1653
	for i := 0; i < len(supportedTsModes); i++ {
		mode := info.soTimestamping & (1 << i)
		if mode != 0 {
			soTimestamping[supportedTsModes[uint(mode)]] = uint(mode)
		}
	}

	supportedTxTypes := []string{
		"HWTSTAMP_TX_OFF",
		"HWTSTAMP_TX_ON",
		"HWTSTAMP_TX_ONESTEP_SYNC",
	}

	txTypes := make(map[string]uint32)

	for i := 0; i < len(supportedTxTypes)+1; i++ {
		txType := info.txTypes & (1 << i)
		if txType != 0 {
			txTypes[supportedTxTypes[txType]] = txType
		}
	}

	supportedRxFilters := []string{
		"HWTSTAMP_FILTER_NONE",
		"HWTSTAMP_FILTER_ALL",
		"HWTSTAMP_FILTER_SOME",
		"HWTSTAMP_FILTER_PTP_V1_L4_EVENT",
		"HWTSTAMP_FILTER_PTP_V1_L4_SYNC",
		"HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ",
		"HWTSTAMP_FILTER_PTP_V2_L4_EVENT",
		"HWTSTAMP_FILTER_PTP_V2_L4_SYNC",
		"HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ",
		"HWTSTAMP_FILTER_PTP_V2_L2_EVENT",
		"HWTSTAMP_FILTER_PTP_V2_L2_SYNC",
		"HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ",
		"HWTSTAMP_FILTER_PTP_V2_EVENT",
		"HWTSTAMP_FILTER_PTP_V2_SYNC",
		"HWTSTAMP_FILTER_PTP_V2_DELAY_REQ",
		"HWTSTAMP_FILTER_NTP_ALL",
	}

	rxFilters := make(map[string]uint32)

	for i := 0; i < len(supportedRxFilters)+1; i++ {
		rxFilter := info.txTypes & (1 << i)
		if rxFilter != 0 {
			rxFilters[supportedRxFilters[rxFilter]] = rxFilter
		}
	}

	tsInfo := TsInfo{
		Cmd:            info.cmd,
		SoTimestamping: soTimestamping,
		PhcIndex:       info.phcIndex,
		TxTypes:        txTypes,
		TxReserved:     info.txReserved,
		RxFilters:      rxFilters,
		RxReserved:     info.rxReserved,
	}

	return tsInfo, nil
}

// ModuleEeprom returns Eeprom information of the given interface name.
func (e *Ethtool) ModuleEeprom(intf string) ([]byte, error) {
	eeprom, _, err := e.getModuleEeprom(intf)
	if err != nil {
		return nil, err
	}

	return eeprom.data[:eeprom.len], nil
}

// ModuleEeprom returns Eeprom information of the given interface name.
func (e *Ethtool) ModuleEepromHex(intf string) (string, error) {
	eeprom, _, err := e.getModuleEeprom(intf)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(eeprom.data[:eeprom.len]), nil
}

// DriverInfo returns driver information of the given interface name.
func (e *Ethtool) DriverInfo(intf string) (DrvInfo, error) {
	i, err := e.getDriverInfo(intf)
	if err != nil {
		return DrvInfo{}, err
	}

	drvInfo := DrvInfo{
		Cmd:         i.cmd,
		Driver:      string(bytes.Trim(i.driver[:], "\x00")),
		Version:     string(bytes.Trim(i.version[:], "\x00")),
		FwVersion:   string(bytes.Trim(i.fw_version[:], "\x00")),
		BusInfo:     string(bytes.Trim(i.bus_info[:], "\x00")),
		EromVersion: string(bytes.Trim(i.erom_version[:], "\x00")),
		Reserved2:   string(bytes.Trim(i.reserved2[:], "\x00")),
		NPrivFlags:  i.n_priv_flags,
		NStats:      i.n_stats,
		TestInfoLen: i.testinfo_len,
		EedumpLen:   i.eedump_len,
		RegdumpLen:  i.regdump_len,
	}

	return drvInfo, nil
}

// GetChannels returns the number of channels for the given interface name.
func (e *Ethtool) GetChannels(intf string) (Channels, error) {
	channels, err := e.getChannels(intf)
	if err != nil {
		return Channels{}, err
	}

	return channels, nil
}

// SetChannels sets the number of channels for the given interface name and
// returns the new number of channels.
func (e *Ethtool) SetChannels(intf string, channels Channels) (Channels, error) {
	channels, err := e.setChannels(intf, channels)
	if err != nil {
		return Channels{}, err
	}

	return channels, nil
}

// GetCoalesce returns the coalesce config for the given interface name.
func (e *Ethtool) GetCoalesce(intf string) (Coalesce, error) {
	coalesce, err := e.getCoalesce(intf)
	if err != nil {
		return Coalesce{}, err
	}
	return coalesce, nil
}

// PermAddr returns permanent address of the given interface name.
func (e *Ethtool) PermAddr(intf string) (string, error) {
	permAddr, err := e.getPermAddr(intf)
	if err != nil {
		return "", err
	}

	if permAddr.data[0] == 0 && permAddr.data[1] == 0 &&
		permAddr.data[2] == 0 && permAddr.data[3] == 0 &&
		permAddr.data[4] == 0 && permAddr.data[5] == 0 {
		return "", nil
	}

	return fmt.Sprintf("%x:%x:%x:%x:%x:%x",
		permAddr.data[0:1],
		permAddr.data[1:2],
		permAddr.data[2:3],
		permAddr.data[3:4],
		permAddr.data[4:5],
		permAddr.data[5:6],
	), nil
}

func (e *Ethtool) ioctl(intf string, data uintptr) error {
	var name [IFNAMSIZ]byte
	copy(name[:], []byte(intf))

	ifr := ifreq{
		ifr_name: name,
		ifr_data: data,
	}

	_, _, ep := unix.Syscall(unix.SYS_IOCTL, uintptr(e.fd), SIOCETHTOOL, uintptr(unsafe.Pointer(&ifr)))
	if ep != 0 {
		return ep
	}

	return nil
}

func (e *Ethtool) getDriverInfo(intf string) (ethtoolDrvInfo, error) {
	drvinfo := ethtoolDrvInfo{
		cmd: ETHTOOL_GDRVINFO,
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&drvinfo))); err != nil {
		return ethtoolDrvInfo{}, err
	}

	return drvinfo, nil
}

func (e *Ethtool) getTimestampInfo(intf string) (ethtoolTsInfo, error) {
	tsinfo := ethtoolTsInfo{
		cmd: ETHTOOL_GET_TS_INFO,
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&tsinfo))); err != nil {
		return ethtoolTsInfo{}, err
	}

	return tsinfo, nil
}

func (e *Ethtool) getChannels(intf string) (Channels, error) {
	channels := Channels{
		Cmd: ETHTOOL_GCHANNELS,
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&channels))); err != nil {
		return Channels{}, err
	}

	return channels, nil
}

func (e *Ethtool) setChannels(intf string, channels Channels) (Channels, error) {
	channels.Cmd = ETHTOOL_SCHANNELS

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&channels))); err != nil {
		return Channels{}, err
	}

	return channels, nil
}

func (e *Ethtool) getCoalesce(intf string) (Coalesce, error) {
	coalesce := Coalesce{
		Cmd: ETHTOOL_GCOALESCE,
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&coalesce))); err != nil {
		return Coalesce{}, err
	}

	return coalesce, nil
}

func (e *Ethtool) getPermAddr(intf string) (ethtoolPermAddr, error) {
	permAddr := ethtoolPermAddr{
		cmd:  ETHTOOL_GPERMADDR,
		size: PERMADDR_LEN,
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&permAddr))); err != nil {
		return ethtoolPermAddr{}, err
	}

	return permAddr, nil
}

func (e *Ethtool) getModuleEeprom(intf string) (ethtoolEeprom, ethtoolModInfo, error) {
	modInfo := ethtoolModInfo{
		cmd: ETHTOOL_GMODULEINFO,
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&modInfo))); err != nil {
		return ethtoolEeprom{}, ethtoolModInfo{}, err
	}

	eeprom := ethtoolEeprom{
		cmd:    ETHTOOL_GMODULEEEPROM,
		len:    modInfo.eeprom_len,
		offset: 0,
	}

	if modInfo.eeprom_len > EEPROM_LEN {
		return ethtoolEeprom{}, ethtoolModInfo{}, fmt.Errorf("eeprom size: %d is larger than buffer size: %d", modInfo.eeprom_len, EEPROM_LEN)
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&eeprom))); err != nil {
		return ethtoolEeprom{}, ethtoolModInfo{}, err
	}

	return eeprom, modInfo, nil
}

func isFeatureBitSet(blocks [MAX_FEATURE_BLOCKS]ethtoolGetFeaturesBlock, index uint) bool {
	return (blocks)[index/32].active&(1<<(index%32)) != 0
}

func setFeatureBit(blocks *[MAX_FEATURE_BLOCKS]ethtoolSetFeaturesBlock, index uint, value bool) {
	blockIndex, bitIndex := index/32, index%32

	blocks[blockIndex].valid |= 1 << bitIndex

	if value {
		blocks[blockIndex].requested |= 1 << bitIndex
	} else {
		blocks[blockIndex].requested &= ^(1 << bitIndex)
	}
}

// FeatureNames shows supported features by their name.
func (e *Ethtool) FeatureNames(intf string) (map[string]uint, error) {
	ssetInfo := ethtoolSsetInfo{
		cmd:       ETHTOOL_GSSET_INFO,
		sset_mask: 1 << ETH_SS_FEATURES,
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&ssetInfo))); err != nil {
		return nil, err
	}

	length := uint32(ssetInfo.data)
	if length == 0 {
		return map[string]uint{}, nil
	} else if length > MAX_GSTRINGS {
		return nil, fmt.Errorf("ethtool currently doesn't support more than %d entries, received %d", MAX_GSTRINGS, length)
	}

	gstrings := ethtoolGStrings{
		cmd:        ETHTOOL_GSTRINGS,
		string_set: ETH_SS_FEATURES,
		len:        length,
		data:       [MAX_GSTRINGS * ETH_GSTRING_LEN]byte{},
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&gstrings))); err != nil {
		return nil, err
	}

	var result = make(map[string]uint)
	for i := 0; i != int(length); i++ {
		b := gstrings.data[i*ETH_GSTRING_LEN : i*ETH_GSTRING_LEN+ETH_GSTRING_LEN]
		key := string(bytes.Trim(b, "\x00"))
		if key != "" {
			result[key] = uint(i)
		}
	}

	return result, nil
}

// Features retrieves features of the given interface name.
func (e *Ethtool) Features(intf string) (map[string]bool, error) {
	names, err := e.FeatureNames(intf)
	if err != nil {
		return nil, err
	}

	length := uint32(len(names))
	if length == 0 {
		return map[string]bool{}, nil
	}

	features := ethtoolGfeatures{
		cmd:  ETHTOOL_GFEATURES,
		size: (length + 32 - 1) / 32,
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&features))); err != nil {
		return nil, err
	}

	var result = make(map[string]bool, length)
	for key, index := range names {
		result[key] = isFeatureBitSet(features.blocks, index)
	}

	return result, nil
}

// Change requests a change in the given device's features.
func (e *Ethtool) Change(intf string, config map[string]bool) error {
	names, err := e.FeatureNames(intf)
	if err != nil {
		return err
	}

	length := uint32(len(names))

	features := ethtoolSfeatures{
		cmd:  ETHTOOL_SFEATURES,
		size: (length + 32 - 1) / 32,
	}

	for key, value := range config {
		if index, ok := names[key]; ok {
			setFeatureBit(&features.blocks, index, value)
		} else {
			return fmt.Errorf("unsupported feature %q", key)
		}
	}

	return e.ioctl(intf, uintptr(unsafe.Pointer(&features)))
}

// Get state of a link.
func (e *Ethtool) LinkState(intf string) (uint32, error) {
	x := ethtoolLink{
		cmd: ETHTOOL_GLINK,
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&x))); err != nil {
		return 0, err
	}

	return x.data, nil
}

// Stats retrieves stats of the given interface name.
func (e *Ethtool) Stats(intf string) (map[string]uint64, error) {
	drvinfo := ethtoolDrvInfo{
		cmd: ETHTOOL_GDRVINFO,
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&drvinfo))); err != nil {
		return nil, err
	}

	if drvinfo.n_stats*ETH_GSTRING_LEN > MAX_GSTRINGS*ETH_GSTRING_LEN {
		return nil, fmt.Errorf("ethtool currently doesn't support more than %d entries, received %d", MAX_GSTRINGS, drvinfo.n_stats)
	}

	gstrings := ethtoolGStrings{
		cmd:        ETHTOOL_GSTRINGS,
		string_set: ETH_SS_STATS,
		len:        drvinfo.n_stats,
		data:       [MAX_GSTRINGS * ETH_GSTRING_LEN]byte{},
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&gstrings))); err != nil {
		return nil, err
	}

	stats := ethtoolStats{
		cmd:     ETHTOOL_GSTATS,
		n_stats: drvinfo.n_stats,
		data:    [MAX_GSTRINGS]uint64{},
	}

	if err := e.ioctl(intf, uintptr(unsafe.Pointer(&stats))); err != nil {
		return nil, err
	}

	var result = make(map[string]uint64)
	for i := 0; i != int(drvinfo.n_stats); i++ {
		b := gstrings.data[i*ETH_GSTRING_LEN : i*ETH_GSTRING_LEN+ETH_GSTRING_LEN]
		strEnd := strings.Index(string(b), "\x00")
		if strEnd == -1 {
			strEnd = ETH_GSTRING_LEN
		}
		key := string(b[:strEnd])
		if len(key) != 0 {
			result[key] = stats.data[i]
		}
	}

	return result, nil
}

// Close closes the ethool handler
func (e *Ethtool) Close() {
	unix.Close(e.fd)
}

// NewEthtool returns a new ethtool handler
func NewEthtool() (*Ethtool, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return nil, err
	}

	return &Ethtool{
		fd: int(fd),
	}, nil
}

// BusInfo returns bus information of the given interface name.
func BusInfo(intf string) (string, error) {
	e, err := NewEthtool()
	if err != nil {
		return "", err
	}
	defer e.Close()
	return e.BusInfo(intf)
}

// DriverName returns the driver name of the given interface name.
func DriverName(intf string) (string, error) {
	e, err := NewEthtool()
	if err != nil {
		return "", err
	}
	defer e.Close()
	return e.DriverName(intf)
}

// Stats retrieves stats of the given interface name.
func Stats(intf string) (map[string]uint64, error) {
	e, err := NewEthtool()
	if err != nil {
		return nil, err
	}
	defer e.Close()
	return e.Stats(intf)
}

// PermAddr returns permanent address of the given interface name.
func PermAddr(intf string) (string, error) {
	e, err := NewEthtool()
	if err != nil {
		return "", err
	}
	defer e.Close()
	return e.PermAddr(intf)
}
