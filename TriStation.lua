--------------------------------------------------------------------------
--
-- TriStation Protocol Plug-in for Wireshark
--
-- date    : April, 4th 2018
-- author  : Younes Dragoni (@ydragoni)
-- author  : Alessandro Di Pinto (@adipinto)
-- contact : secresearch [ @ ] nozominetworks [ . ] com
--
--------------------------------------------------------------------------

ts_proto = Proto("TriStation" , "TriStation Protocol")
-- CRC32 module loading
pkt_table = {}
crc_table = {}
pkt_max_number = 0

-- TS command list
local TS_names = {
  [-1]= 'Not set',
   [0]= 'Start download all',
   [1]= 'Start download change',
   [2]= 'Update configuration',
   [3]= 'Upload configuration',
   [4]= 'Set I/O addresses',
   [5]= 'Allocate network',
   [6]= 'Load vector table',
   [7]= 'Set calendar',
   [8]= 'Get calendar',
   [9]= 'Set scan time',
   [10]= 'End download all',
   [11]= 'End download change',
   [12]= 'Cancel download change',
   [13]= 'Attach TRICON',
   [14]= 'Set I/O address limits',
   [15]= 'Configure module',
   [16]= 'Set multiple point values',
   [17]= 'Enable all points',
   [18]= 'Upload vector table',
   [19]= 'Get CP status ',
   [20]= 'Run program',
   [21]= 'Halt program',
   [22]= 'Pause program',
   [23]= 'Do single scan',
   [24]= 'Get chassis status',
   [25]= 'Get minimum scan time',
   [26]= 'Set node number',
   [27]= 'Set I/O point values',
   [28]= 'Get I/O point values',
   [29]= 'Get MP status',
   [30]= 'Set retentive values',
   [31]= 'Adjust clock calendar',
   [32]= 'Clear module alarms',
   [33]= 'Get event log',
   [34]= 'Set SOE block',
   [35]= 'Record event log',
   [36]= 'Get SOE data',
   [37]= 'Enable OVD',
   [38]= 'Disable OVD',
   [39]= 'Enable all OVDs',
   [40]= 'Disable all OVDs',
   [41]= 'Process MODBUS',
   [42]= 'Upload network',
   [43]= 'Set lable',
   [44]= 'Configure system variables',
   [45]= 'Deconfigure module',
   [46]= 'Get system variables',
   [47]= 'Get module types',
   [48]= 'Begin conversion table download',
   [49]= 'Continue conversion table download',
   [50]= 'End conversion table download',
   [51]= 'Get conversion table',
   [52]= 'Set ICM status',
   [53]= 'Broadcast SOE data available',
   [54]= 'Get module versions',
   [55]= 'Allocate program',
   [56]= 'Allocate function',
   [57]= 'Clear retentives',
   [58]= 'Set initial values',
   [59]= 'Start TS2 program download',
   [60]= 'Set TS2 data area',
   [61]= 'Get TS2 data',
   [62]= 'Set TS2 data',
   [63]= 'Set program information',
   [64]= 'Get program information',
   [65]= 'Upload program',
   [66]= 'Upload function',
   [67]= 'Get point groups',
   [68]= 'Allocate symbol table',
   [69]= 'Get I/O address',
   [70]= 'Resend I/O address',
   [71]= 'Get program timing',
   [72]= 'Allocate multiple functions',
   [73]= 'Get node number',
   [74]= 'Get symbol table',
   [75]= 'Unk75',
   [76]= 'Unk76',
   [77]= 'Unk77',
   [78]= 'Unk78',
   [79]= 'Unk79',
   [80]= 'Go to DOWNLOAD mode',
   [81]= 'Unk81',
   [83]= 'Unk83',
   [100]= 'Command rejected',
   [101]= 'Download all permitted',
   [102]= 'Download change permitted',
   [103]= 'Modification accepted',
   [104]= 'Download cancelled',
   [105]= 'Program accepted',
   [106]= 'TRICON attached',
   [107]= 'I/O addresses set',
   [108]= 'Get CP status response',
   [109]= 'Program is running',
   [110]= 'Program is halted',
   [111]= 'Program is paused',
   [112]= 'End of single scan',
   [113]= 'Get chassis configuration response',
   [114]= 'Scan period modified',
   [115]= '<115>',
   [116]= '<116>',
   [117]= 'Module configured',
   [118]= '<118>',
   [119]= 'Get chassis status response',
   [120]= 'Vectors response',
   [121]= 'Get I/O point values response',
   [122]= 'Calendar changed',
   [123]= 'Configuration updated',
   [124]= 'Get minimum scan time response',
   [125]= '<125>',
   [126]= 'Node number set',
   [127]= 'Get MP status response',
   [128]= 'Retentive values set',
   [129]= 'SOE block set',
   [130]= 'Module alarms cleared',
   [131]= 'Get event log response',
   [132]= 'Symbol table ccepted',
   [133]= 'OVD enable accepted',
   [134]= 'OVD disable accepted',
   [135]= 'Record event log response',
   [136]= 'Upload network response',
   [137]= 'Get SOE data response',
   [138]= 'Alocate network accepted',
   [139]= 'Load vector table accepted',
   [140]= 'Get calendar response',
   [141]= 'Label set',
   [142]= 'Get module types response',
   [143]= 'System variables configured',
   [144]= 'Module deconfigured',
   [145]= '<145>',
   [146]= '<146>',
   [147]= 'Get conversion table response',
   [148]= 'ICM print data sent',
   [149]= 'Set ICM status response',
   [150]= 'Get system variables response',
   [151]= 'Get module versions response',
   [152]= 'Process MODBUS response',
   [153]= 'Allocate program response',
   [154]= 'Allocate function response',
   [155]= 'Clear retentives response',
   [156]= 'Set initial values response',
   [157]= 'Set TS2 data area response',
   [158]= 'Get TS2 data response',
   [159]= 'Set TS2 data response',
   [160]= 'Set program information reponse',
   [161]= 'Get program information response',
   [162]= 'Upload program response',
   [163]= 'Upload function response',
   [164]= 'Get point groups response',
   [165]= 'Allocate symbol table response',
   [166]= 'Program timing response',
   [167]= 'Disable points full',
   [168]= 'Allocate multiple functions response',
   [169]= 'Get node number response',
   [170]= 'Symbol table response',
   [200]= 'Wrong command',
   [201]= 'Load is in progress',
   [202]= 'Bad clock calendar data',
   [203]= 'Control program not halted',
   [204]= 'Control program checksum error',
   [205]= 'No memory available',
   [206]= 'Control program not valid',
   [207]= 'Not loading a control program',
   [208]= 'Network is out of range',
   [209]= 'Not enough arguments',
   [210]= 'A Network is missing',
   [211]= 'The download time mismatches',
   [212]= 'Key setting prohibits this operation',
   [213]= 'Bad control program version',
   [214]= 'Command not in correct sequence',
   [215]= '<215>',
   [216]= 'Bad Index for a module',
   [217]= 'Module address is invalid',
   [218]= '<218>',
   [219]= '<219>',
   [220]= 'Bad offset for an I/O point',
   [221]= 'Invalid point type',
   [222]= 'Invalid Point Location',
   [223]= 'Program name is invalid',
   [224]= '<224>',
   [225]= '<225>',
   [226]= '<226>',
   [227]= 'Invalid module type',
   [228]= '<228>',
   [229]= 'Invalid table type',
   [230]= '<230>',
   [231]= 'Invalid network continuation',
   [232]= 'Invalid scan time',
   [233]= 'Load is busy',
   [234]= 'An MP has re-educated',
   [235]= 'Invalid chassis or slot',
   [236]= 'Invalid SOE number',
   [237]= 'Invalid SOE type',
   [238]= 'Invalid SOE state',
   [239]= 'The variable is write protected',
   [240]= 'Node number mismatch',
   [241]= 'Command not allowed',
   [242]= 'Invalid sequence number',
   [243]= 'Time change on non-master TRICON',
   [244]= 'No free Tristation ports',
   [245]= 'Invalid Tristation I command',
   [246]= 'Invalid TriStation 1131 command',
   [247]= 'Only one chassis allowed',
   [248]= 'Bad variable address',
   [249]= 'Response overflow',
   [250]= 'Invalid bus',
   [251]= 'Disable is not allowed',
   [252]= 'Invalid length',
   [253]= 'Point cannot be disabled',
   [254]= 'Too many retentive variables',
   [255]= 'LOADER_CONNECT',
   [256]= 'Unknown reject code'
 }

message_type 	    = ProtoField.uint16("ts.message_type", "TCM_type", base.HEX) 			
crc16 			      = ProtoField.uint16("ts.crc16", "crc16", base.HEX)						
crc32 			      = ProtoField.uint32("ts.TScksum", "TScksum", base.HEX)					
cid 			        = ProtoField.uint8("ts.ts_cid", "cid", base.DEC) 					
message_length 	  = ProtoField.int16("ts.message_length", "data_len", base.DEC) 	
ts_checksum 	    = ProtoField.uint16("ts.ts_chks", "checksum", base.HEX)			
ts_function		    = ProtoField.uint32("ts.ts_function", "func", base.HEX)			
ts_program		    = ProtoField.uint32("ts.ts_program", "program", base.HEX)	
ts_full_program		= ProtoField.new("Programs","ts.ts_full_program",  ftypes.BYTES)	
ts_signature		  = ProtoField.uint32("ts.ts_signature", "triton signature", base.HEX)		
ts_sequence 	    = ProtoField.uint8("ts.ts_sequence", "seq_num", base.DEC) 			
ts_cmd 			      = ProtoField.int16("ts.ts_cmd",	"Command", base.DEC)				
ts_module		      = ProtoField.uint8("ts.ts_module", "module_type", base.HEX)		
ts_unknown 		    = ProtoField.int64("ts.ts_unk", "unk", base.DEC)					
ts_length 		    = ProtoField.int64("ts.ts_len", "data_len", base.DEC)				
ts_cp_fstat 	    = ProtoField.uint64("ts.ts_cp_fstat", "fstat", base.DEC)				
ts_cp_keyState 	  = ProtoField.uint8("ts.ts_cp_keyState", "keyState", base.HEX) 	
ts_cp_runState 	  = ProtoField.uint8("ts.ts_cp_runState", "runState", base.HEX) 		
ts_path	     	    = ProtoField.uint8("ts.ts_path", "path", base.DEC) 				

ts_proto.fields = {
					message_type,
          crc16,
          crc32,
					message_length,
					cid,
					ts_cmd,
					ts_sequence,
					ts_unknown,
					ts_checksum,
					ts_length,
					ts_cp_keyState,
					ts_cp_runState,
					ts_cp_fstat,
					ts_function,
          ts_program,
          ts_signature,
					ts_project,
					ts_path,
          ts_module,
          ts_full_program
}

function ts_proto.dissector(buffer, pinfo, tree)
  length = buffer:len()
  pinfo.cols.protocol = ts_proto.name

  local subtree = tree:add(ts_proto, buffer(), "TriStation Protocol")
  tcm_data = subtree:add(buffer(4),  "TCM communication: ")
  local opcode = buffer(0,1):uint()
  local opcode_name = get_tcm_opcode(opcode)

  tcm_data:add_le(opcode, buffer(0,1)):append_text(" [" .. opcode_name .. "]")
  tcm_data:add_le(buffer(1,1), "Channel: ", buffer(1,1):uint())
  tcm_len = tcm_data:add_le(message_length, buffer(2,2))

  if (buffer(2,2):uint() ~= 0) then 
  	ts_data = subtree:add(buffer(4,buffer(2,2):le_uint()),  "TS communication: ")
    local direction = buffer(4,1):le_uint()
    local direction_type = get_comm_type(direction)
    ts_data:add(ts_path, buffer(4,1)):append_text(" [" .. direction_type .. "]") 	
    ts_data:add(cid, buffer(5,1))
    cmd_data = ts_data:add(ts_cmd, buffer(6,1):le_uint())
    cmd_detail	= TS_names[buffer(6,1):le_uint()]
    if(cmd_detail ~= nil) then
    	-- Supported command
		  cmd_data:append_text(" [" .. cmd_detail .. "]")
	else
		-- Command unknown
		cmd_data:append_text(" [unknown TS command]")
	end
    ts_seq = ts_data:add(ts_sequence, buffer(7,1))
    unknown_value = ts_data:add(ts_unknown, buffer(8,2))
    checksum_value = ts_data:add(ts_checksum, buffer(10,2)):append_text(" (" .. buffer(10,2):uint() .. ")")
    len_value = ts_data:add_le(ts_length, buffer(12,2))
    -- Create function for each known response and call based on the reply
    if buffer(6,1):le_uint() == 108 then cp_status_resp(buffer, cmd_data)      				    
    elseif buffer(6,1):le_uint() == 55 then allocate_program(buffer, cmd_data, pinfo) 				    
    elseif buffer(6,1):le_uint() == 56 then allocate_function(buffer, cmd_data) 			   
    elseif buffer(6,1):le_uint() == 59 then ts2_program_download(buffer, cmd_data) 			  
    elseif buffer(6,1):le_uint() == 151 then get_t2_data_module_version(buffer, cmd_data) 
    elseif buffer(6,1):le_uint() == 65 then upload_program_req(buffer, cmd_data) 			   
    elseif buffer(6,1):le_uint() == 66 then upload_function_req(buffer, cmd_data) 			 
    elseif buffer(6,1):le_uint() == 163 then upload_function_res(buffer, cmd_data) 			  
    elseif buffer(6,1):le_uint() == 162 then upload_program_res(buffer, cmd_data) 			 
    elseif buffer(6,1):le_uint() == 119 then get_chassis_status_resp(buffer, cmd_data) 		
    elseif buffer(6,1):le_uint() == 106 then tricon_attached(buffer, cmd_data) 				    
    else
    	if ((buffer(12,2):le_uint() - 10) ~= 0) then
    		ts_raw = ts_data:add(buffer(14,buffer(12,2):le_uint() - 10),  "Data: " .. buffer(14,buffer(12,2):le_uint() - 10))
    	end
    end

    crc16_value = tree:add(crc16, buffer(length-2)):append_text(" (" .. buffer(length-2):uint() .. ")")
  else  -- No TS data
  	crc16_value = tree:add(crc16, buffer(length-2)):append_text(" (" .. buffer(length-2):uint() .. ")")
  end   
end

function get_led_status(bit)
  local led_status = "Unknown status"

  if bit == "1" then led_status = "ON"
  elseif bit == "0" then led_status = "OFF" end

  return led_status
end

-- Function: TCM function list
function get_tcm_opcode(opcode)
  local opcode_name = "Unknown command"

  if opcode == 1 then opcode_name = "CONNECT REQUEST"
  elseif opcode == 2 then opcode_name = "CONNECT REPLY"
  elseif opcode == 3 then opcode_name = "DISCONN REPLY"
  elseif opcode == 4 then opcode_name = "DISCONN REQUEST"
  elseif opcode == 5 then opcode_name = "COMMAND REPLY"
  elseif opcode == 6 then opcode_name = "PING"
  elseif opcode == 7 then opcode_name = "CONN LIMIT REACHED"
  elseif opcode == 8 then opcode_name = "NOT CONNECTED"
  elseif opcode == 9 then opcode_name = "MPS ARE DEAD"
  elseif opcode == 10 then opcode_name = "ACCESS DENIED" 
  elseif opcode == 11 then opcode_name = "CONNECTION FAILED" end

  return opcode_name
end

-- Function: TS modules list
function get_module_type(opcode)
	local opcode_name = "Unknown module"

	if opcode == 255 then opcode_name = "3008/N Tricon Enhanced Main Processor"
	elseif opcode == 1 then opcode_name = "3501/E/T/TN Discrete Input, 115 V, 32 points"
	elseif opcode == 2 then opcode_name = "3502/E/EN Discrete Input, 48 V, 32 points"
	elseif opcode == 3 then opcode_name = "3503/E/EN Discrete Input, 24 V, 32 points"
	elseif opcode == 7 then opcode_name = "3505/E/EN Discrete Input, 24 V, Low Threshold, 32 points"
	elseif opcode == 11 then opcode_name = "3508/E Discrete Input, 230 V, 32 points"
	elseif opcode == 17 then opcode_name = "3601/E/T/TN Discrete Output, 115 VAC, 16 points"
	elseif opcode == 19 then opcode_name = "3603/B/E/T/TN Discrete Output, 120 VDC, 16 points"
	elseif opcode == 20 then opcode_name = "3604/E/EN Discrete Output, 24 VDC, 16 points"
	elseif opcode == 23 then opcode_name = "3608/E Discrete Output, 48 VAC, 16 points"
	elseif opcode == 24 then opcode_name = "3607/E/EN Discrete Output, 48 VDC, 16 points"
	elseif opcode == 29 then opcode_name = "6603 Discrete Output, 24 VDC, 16 points"
	elseif opcode == 30 then opcode_name = "6602 Discrete Output, 48 VDC, 16 points"
	elseif opcode == 31 then opcode_name = "6601 Discrete Output, 115 VAC, 16 points"
	elseif opcode == 32 then opcode_name = "3701/N Analog Input, 10 V input, 32 points"
	elseif opcode == 33 then opcode_name = "3700/A/AN Analog Input,  5 V input, 32 points"
	elseif opcode == 38 then opcode_name = "3510/N Pulse Input, 8 points"
	elseif opcode == 40 then opcode_name = "3801 Analog I/O, 10 V inp, 4-20ma out, 8 inputs, 4 outputs"
	elseif opcode == 41 then opcode_name = "3800 Analog I/O,  5 V inp, 4-20ma out, 8 inputs, 4 outputs"
	elseif opcode == 42 then opcode_name = "6810 Analog Output, 4-20ma, 4 points; Pulse Input, 4 points"
	elseif opcode == 45 then opcode_name = "3511 Enhanced Pulse Input, 8 points"
	elseif opcode == 47 then opcode_name = "3515 Pulse Totalizer Input, 32 Data points, 32 Reset points"
	elseif opcode == 48 then opcode_name = "4119/A/AN EICM (Intelligent Communications Module)"
	elseif opcode == 49 then opcode_name = "420-/N,421-/N Remote Extender Module, Primary/Remote"
	elseif opcode == 50 then opcode_name = "6211 ICM (Intelligent Communications Module)"
	elseif opcode == 51 then opcode_name = "4509 Honeywell Data Highway Interface Module (HIM)"
	elseif opcode == 52 then opcode_name = "4409 Safety Manager Module"
	elseif opcode == 53 then opcode_name = "6215 Honeywell Data Highway Interface Module (HIM)" 
	elseif opcode == 54 then opcode_name = "GPSI Global Positioning System Interface"
	elseif opcode == 55 then opcode_name = "4329/N/G NCM (Network Communications Module)"
	elseif opcode == 56 then opcode_name = "4609/N ACM (Advanced Communications Module)"
	elseif opcode == 57 then opcode_name = "4351B TCM-B (Tricon Communication Module/B - Copper)"
	elseif opcode == 58 then opcode_name = "4352B TCM-B (Tricon Communication Module/B - Fiber)"
	elseif opcode == 59 then opcode_name = "4353 TCM/OPC (Tricon Communication Module OPC - Copper)"
	elseif opcode == 60 then opcode_name = "4354 TCM/OPC (Tricon Communication Module OPC - Fiber)"
	elseif opcode == 71 then opcode_name = "3531 Discrete Input (simplx), 115 V, 32 points"
	elseif opcode == 72 then opcode_name = "3532 Discrete Input (simplx), 48 V, 32 points"
	elseif opcode == 73 then opcode_name = "3533 Discrete Input (simplx), 24 V, 32 points"
	elseif opcode == 84 then opcode_name = "4351 TCM (Tricon Communications Module - Copper)"
	elseif opcode == 85 then opcode_name = "4352 TCM (Tricon Communications Module - Fiber)"
	elseif opcode == 86 then opcode_name = "4351A TCM-A (Tricon Communication Module/A - Copper)"
	elseif opcode == 87 then opcode_name = "4352A/N TCM-A (Tricon Communication Module/A - Fiber)"
	elseif opcode == 88 then opcode_name = "3664 Dual Discrete Output, 24 V, 32 points, Serial"
	elseif opcode == 89 then opcode_name = "3674 Dual Discrete Output, 24 V, 32 points, Fail-Safe"
	elseif opcode == 90 then opcode_name = "3667 Dual Discrete Output, 48 V, 32 points, Serial"
	elseif opcode == 91 then opcode_name = "3677 Dual Discrete Output, 48 V, 32 points, Parallel"
	elseif opcode == 92 then opcode_name = "3663 Dual Discrete Output, 120V, 32 points, Serial"
	elseif opcode == 93 then opcode_name = "3673 Dual Discrete Output, 120V, 32 points, Parallel"
	elseif opcode == 94 then opcode_name = "3720 Enh Analog Input, 5V, 64 points, Configurable"
	elseif opcode == 95 then opcode_name = "3721/N Enh Differential Analog Input, +/-5V, 32 points, Configurable"
	elseif opcode == 104 then opcode_name = "3805/E/H/EN Analog Output, 4-20ma, 8 points"
	elseif opcode == 105 then opcode_name = "3807 Servo Control Analog Output, -60 to +60mA"
	elseif opcode == 107 then opcode_name = "6613 Supv Disc Output, 24 V, 16 points"
	elseif opcode == 106 then opcode_name = "3806 Analog Output, 4-20ma (6 pts), 4-320ma (2 pts)"
	elseif opcode == 108 then opcode_name = "6612 Supv Disc Output, 48 V, 16 points"
	elseif opcode == 109 then opcode_name = "6617 Supv Disc Output, 120 V, 16 points"
	elseif opcode == 110 then opcode_name = "6703 Analog Input (isolated),  2 V, 16 points"
	elseif opcode == 111 then opcode_name = "3635/E Discrete Output (simplx), Relay Cntct, Norm clsd, 32 pts"
	elseif opcode == 112 then opcode_name = "3636/R/T/TN Discrete Output (simplx), Relay Cntct, Norm open, 32 pts"
	elseif opcode == 113 then opcode_name = "3611/E Supv Discrete Output, 115 VAC, 8 points"
	elseif opcode == 129 then opcode_name = "6507 Discrete Input, 120 VDC, 32 points"
	elseif opcode == 130 then opcode_name = "6502 Discrete Input, 48 VDC, 32 points"
	elseif opcode == 133 then opcode_name = "6503 Discrete Input, 24 VDC, 32 points"
	elseif opcode == 134 then opcode_name = "6501 Discrete Input, 115 VAC, 32 points"
	elseif opcode == 136 then opcode_name = "6508 Discrete Input, 48 VAC, 32 points"
	elseif opcode == 138 then opcode_name = "6708 Isol Thermocouple Input Type E dgC, 16 points"
	elseif opcode == 139 then opcode_name = "6708 Isol Thermocouple Input Type J dgC, 16 points"
	elseif opcode == 140 then opcode_name = "6708 Isol Thermocouple Input Type K dgC, 16 points" 
	elseif opcode == 141 then opcode_name = "6708 Isol Thermocouple Input Type T dgC, 16 points"
	elseif opcode == 146 then opcode_name = "3706/A/AN Non-Isol Thermocouple Input Type J dgF  32 points"
	elseif opcode == 147 then opcode_name = "3706/A/AN Non-Isol Thermocouple Input Type K dgF  32 points"
	elseif opcode == 148 then opcode_name = "3706/A/AN Non-Isol Thermocouple Input Type T dgF  32 points"
	elseif opcode == 149 then opcode_name = "3706/A/AN Non-Isol Thermocouple Input Type J dgC  32 points"
	elseif opcode == 150 then opcode_name = "3706/A/AN Non-Isol Thermocouple Input Type K dgC  32 points"
	elseif opcode == 151 then opcode_name = "3706/A/AN Non-Isol Thermocouple Input Type T dgC  32 points"
	elseif opcode == 152 then opcode_name = "3704/E/EN Analog Input,  5 V, DnS, 64 points"
	elseif opcode == 153 then opcode_name = "3704/E/EN Analog Input, 10 V, DnS, 64 points"
	elseif opcode == 154 then opcode_name = "3704/E/EN Analog Input,  5 V, UpS, 64 points"
	elseif opcode == 155 then opcode_name = "3704/E/EN Analog Input, 10 V, UpS, 64 points"
	elseif opcode == 156 then opcode_name = "3504/E/EN Discrete Input, 24 VDC, 64 points"
	elseif opcode == 157 then opcode_name = "3504/E/EN Discrete Input, 48 VDC, 64 points"
	elseif opcode == 158 then opcode_name = "3625/N Supervised Discrete Output, 24V, 32 points, Configurable"
	elseif opcode == 160 then opcode_name = "6700 Analog Input,  5 V, DnS, 32 points"
	elseif opcode == 161 then opcode_name = "6700 Analog Input, 10 V, DnS, 32 points"
	elseif opcode == 162 then opcode_name = "6700 Analog Input,  5 V, UpS, 32 points"
	elseif opcode == 163 then opcode_name = "6700 Analog Input, 10 V, UpS, 32 points"
	elseif opcode == 180 then opcode_name = "3703/E/EN Enh Isol Analog Input,  5 V, DnS, 16 points"
	elseif opcode == 181 then opcode_name = "3703/E/EN Enh Isol Analog Input, 10 V, DnS, 16 points"
	elseif opcode == 182 then opcode_name = "3703/E/EN 3Enh Isol Analog Input,  5 V, UpS, 16 points"
	elseif opcode == 183 then opcode_name = "3703/E/EN Enh Isol Analog Input, 10 V, UpS, 16 points"
	elseif opcode == 184 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type J dgC DnS, 16 points"
	elseif opcode == 185 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type K dgC DnS, 16 points"
	elseif opcode == 186 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type T dgC DnS, 16 points"
	elseif opcode == 187 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type E dgC DnS, 16 points"
	elseif opcode == 192 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type J dgF DnS, 16 points"
	elseif opcode == 193 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type K dgF DnS, 16 points"
	elseif opcode == 194 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type T dgF DnS, 16 points"
	elseif opcode == 195 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type E dgF DnS, 16 points"
	elseif opcode == 200 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type J dgC UpS, 16 points"
	elseif opcode == 201 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type K dgC UpS, 16 points"
	elseif opcode == 201 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type T dgC UpS, 16 points"
	elseif opcode == 202 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type E dgC UpS, 16 points"
	elseif opcode == 208 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type J dgF UpS, 16 points"
	elseif opcode == 209 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type K dgF UpS, 16 points"
	elseif opcode == 210 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type T dgF UpS, 16 points" 
	elseif opcode == 211 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type E dgF UpS, 16 points"
	elseif opcode == 216 then opcode_name = "3614/E Supv Discrete Output, 24 V, OFF STATE SCD, 8 points"
	elseif opcode == 217 then opcode_name = "3614/E Supv Discrete Output, 24 V, 8 points"
	elseif opcode == 218 then opcode_name = "3617/E Supv Discrete Output, 48 V, OFF STATE SCD, 8 points"
	elseif opcode == 219 then opcode_name = "3617/E Supv Discrete Output, 48 V, 8 points"
	elseif opcode == 220 then opcode_name = "3613/E Supv Discrete Output, 120 V, OFF STATE SCD, 8 points"
	elseif opcode == 221 then opcode_name = "3613/E Supv Discrete Output, 120 V, 8 points"
	elseif opcode == 222 then opcode_name = "3615/E Supv Disc Output, 24 V, OFF STATE SCD, Low Power, 8 points"
	elseif opcode == 223 then opcode_name = "3615/E Supv Disc Output, 24 V, Low Power, 8 points"
	elseif opcode == 224 then opcode_name = "3564 Single Discrete Input, 24 V, 64 points"
	elseif opcode == 225 then opcode_name = "3564 Single Discrete Input, 24 V, 64 points, Non-Critical"
	elseif opcode == 226 then opcode_name = "3562 Single Discrete Input, 48 V, 64 points"
	elseif opcode == 227 then opcode_name = "3562 Single Discrete Input, 48 V, 64 points, Non-Critical"
	elseif opcode == 228 then opcode_name = "3561 Single Discrete Input, 120V, 64 points"
	elseif opcode == 229 then opcode_name = "3561 Single Discrete Input, 120V, 64 points, Non-Critical"
	elseif opcode == 230 then opcode_name = "356X Single Discrete Input, 115V, 64 points"
	elseif opcode == 231 then opcode_name = "356X Single Discrete Input, 115V, 64 points, Non-Critical"
	elseif opcode == 232 then opcode_name = "3624/N Supervised Discrete Output, 24 V, 16 points"
	elseif opcode == 233 then opcode_name = "3624 Supervised Discrete Output, 24 V, 16 points, Non-Supervised"
	elseif opcode == 234 then opcode_name = "3627 Supervised Discrete Output, 48 V, 16 points"
	elseif opcode == 235 then opcode_name = "3627 Supervised Discrete Output, 48 V, 16 points, Non-Supervised"
	elseif opcode == 236 then opcode_name = "3623/T/TN Supervised Discrete Output, 120V, 16 points"
	elseif opcode == 237 then opcode_name = "3623 Supervised Discrete Output, 120V, 16 points, Non-Supervised"
	elseif opcode == 238 then opcode_name = "362X Supervised Discrete Output, 115V, 16 points"
	elseif opcode == 239 then opcode_name = "362X Supervised Discrete Output, 115V, 16 points, Non-Supervised"
	elseif opcode == 208 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type J dgF UpS, 16 points"
	elseif opcode == 209 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type K dgF UpS, 16 points"
	elseif opcode == 210 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type T dgF UpS, 16 points" 
	elseif opcode == 211 then opcode_name = "3708/E/EN Enh Isol Thermocouple Input Type E dgF UpS, 16 points"
	elseif opcode == 216 then opcode_name = "3614/E Supv Discrete Output, 24 V, OFF STATE SCD, 8 points"
	elseif opcode == 217 then opcode_name = "3614/E Supv Discrete Output, 24 V, 8 points"
	elseif opcode == 218 then opcode_name = "3617/E Supv Discrete Output, 48 V, OFF STATE SCD, 8 points"
	elseif opcode == 219 then opcode_name = "3617/E Supv Discrete Output, 48 V, 8 points"
	elseif opcode == 220 then opcode_name = "3613/E Supv Discrete Output, 120 V, OFF STATE SCD, 8 points"
	elseif opcode == 221 then opcode_name = "3613/E Supv Discrete Output, 120 V, 8 points"
	elseif opcode == 222 then opcode_name = "3615/E Supv Disc Output, 24 V, OFF STATE SCD, Low Power, 8 points"
	elseif opcode == 223 then opcode_name = "3615/E Supv Disc Output, 24 V, Low Power, 8 points"
	elseif opcode == 224 then opcode_name = "3564 Single Discrete Input, 24 V, 64 points"
	elseif opcode == 225 then opcode_name = "3564 Single Discrete Input, 24 V, 64 points, Non-Critical"
	elseif opcode == 226 then opcode_name = "3562 Single Discrete Input, 48 V, 64 points"
	elseif opcode == 227 then opcode_name = "3562 Single Discrete Input, 48 V, 64 points, Non-Critical"
	elseif opcode == 228 then opcode_name = "3561 Single Discrete Input, 120V, 64 points"
	elseif opcode == 229 then opcode_name = "3561 Single Discrete Input, 120V, 64 points, Non-Critical"
	elseif opcode == 230 then opcode_name = "356X Single Discrete Input, 115V, 64 points"
	end

  return opcode_name
end

-- Function: communication direction
function get_comm_type(direction)
  local comm_type = "Unknown direction"

      if direction == 0 then comm_type = "Workstation --> Controller"
  	elseif direction == 1 then comm_type = "Controller --> Workstation" end

  return comm_type
end

-- Function: CP Get Status response
function cp_status_resp(buffer, subtree)

  subtree:add(buffer(14,2), "unk:", buffer(14,2):uint())
  subtree:add(buffer(16,1), "loadIn:", buffer(16,1):uint())
  subtree:add(buffer(17,1), "modIn:", buffer(17,1):uint())
  subtree:add(buffer(18,1), "loadState:", buffer(18,1):uint())
  subtree:add(buffer(19,1), "singleScan:", buffer(19,1):uint())
  subtree:add(buffer(20,1), "cpValid:", buffer(20,1):uint())
  if buffer(21,1):uint() == 0 then
  	subtree:add(ts_cp_keyState, buffer(21,1)):append_text("	[Stop] ")
  elseif buffer(21,1):uint() == 1 then
  	subtree:add(ts_cp_keyState, buffer(21,1)):append_text("	[Program] ")
  elseif buffer(21,1):uint() == 2 then
  	subtree:add(ts_cp_keyState, buffer(21,1)):append_text("	[Run] ")
  elseif buffer(21,1):uint() == 3 then
  	subtree:add(ts_cp_keyState, buffer(21,1)):append_text("	[Remote] ")
  end
  if buffer(22,1):le_uint() == 0 then
  	subtree:add(ts_cp_runState, buffer(22,1)):append_text("	[Running] ")
  elseif buffer(22,1):le_uint() == 1 then
  	subtree:add(ts_cp_runState, buffer(22,1)):append_text("	[Stop] ")
  elseif buffer(22,1):le_uint() == 2 then
  	subtree:add(ts_cp_runState, buffer(22,1)):append_text("	[Pause] ")
  end
  subtree:add_le(buffer(27,4), "my:", buffer(27,4):uint())
  subtree:add_le(buffer(30,4), "us:", buffer(30,4):uint())
  subtree:add_le(buffer(34,4), "ds:", buffer(34,4):uint())
  subtree:add_le(buffer(38,4), "heapMin:", buffer(38,4):uint())
  subtree:add_le(buffer(42,4), "heapMax:", buffer(42,4):uint())
  subtree:add(ts_cp_fstat, buffer(54,4))
  subtree:add(buffer(70,2), "project_minor:", buffer(70,2):uint())
  subtree:add(buffer(72,2), "project_major:", buffer(72,2):uint())
  subtree:add_le(buffer(74,4), "project_timestamp:", buffer(74,4):uint())
  subtree:add(buffer(80,10), "project:", buffer(80,10):string())
  -- Unknown data: to parse
  if ((buffer(12,2):le_uint() - 10) ~= 0) then
  	ts_raw = ts_data:add(buffer(90,buffer(12,2):le_uint() - 84),  "Data: " .. buffer(90,buffer(12,2):le_uint() - 84))
  end
end

-- Function: Allocate Functions
function allocate_function(buffer, subtree)
	
  subtree:add_le(buffer(14,2), "id:", buffer(14,2):le_uint())
  subtree:add_le(buffer(16,2), "next:", buffer(16,2):le_uint())
  subtree:add_le(buffer(18,2), "full_chunks:", buffer(18,2):le_uint())
  subtree:add_le(buffer(20,2), "offset:", buffer(20,2):le_uint())
  subtree:add_le(buffer(22,2), "func_blocks (4 bytes):", buffer(22,2):le_uint())
  blocks = (buffer(22,2):le_uint())*4
  buff = 24
  local count = 1
  p = 0
  ts_func = subtree:add(buffer(24, blocks),  "Functions: ", blocks)  -- split functions based on the blocks number
  while p < blocks-4 do
  	p = p + 4
  	function_hex = ts_func:add(ts_function, buffer(buff,4)):append_text("	[" .. count .. "]")
  	buff = buff + 4
    count = count + 1
    if (p+4 == blocks)  then
      crc32_value = ts_func:add(crc32, buffer(buff,4)):append_text(" (" .. buffer(buff,4):uint() .. ")")
    end
  end
end

-- Function: Allocate Programs
function allocate_program(buffer, subtree, pinfo)
 
  subtree:add_le(buffer(14,2), "id:", buffer(14,2):le_uint())
  subtree:add_le(buffer(16,2), "next:", buffer(16,2):le_uint())
  subtree:add_le(buffer(18,2), "full_chunks:", buffer(18,2):le_uint())
  subtree:add_le(buffer(20,2), "offset:", buffer(20,2):le_uint())
  subtree:add_le(buffer(22,2), "program_blocks (4 bytes):", buffer(22,2):le_uint())
  id = buffer(14,2):le_uint()
  chunked = buffer(18,2):le_uint()
  blocks_num = buffer(22,2):le_uint()
  offset = buffer(20,2):le_uint()

  blocks = (buffer(22,2):le_uint())*4
  buff = 24
  local count = 1
  p = 0
  ts_prog = subtree:add(ts_full_program, buffer(24, blocks-8))  -- split programs based on the blocks number
  while p < blocks-8 do
  	p = p + 4
    program_hex = ts_prog:add(ts_program, buffer(buff,4)):append_text("	[" .. count .. "]")
  	buff = buff + 4
    count = count + 1
    if (p+8 == blocks)  then
      sign = buffer(buff,4):le_uint()
      checksum, mlw = crc32_calc(chunked, id, Struct.fromhex(tostring(buffer(24, blocks):bytes())), blocks_num, offset, pinfo, sign)
      if checksum~=0 then
        if mlw then
          malicious_signature = ts_prog:add(ts_signature, buffer(buff,4))
          crc32_value = ts_prog:add(crc32, buffer(buff+4,4)):append_text(" (" .. buffer(buff+4,4):uint() .. ")")
          subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "TRITON malware detected! ")
        else
          program_hex = ts_prog:add(ts_program, buffer(buff,4)):append_text("	[" .. count .. "]")
          crc32_value = ts_prog:add(crc32, buffer(buff+4,4)):append_text(" (" .. buffer(buff+4,4):uint() .. ")")
        end
      else
        crc32_value = subtree:add(buffer(buff,4), "crc32: "):append_text(" [ chunked program ]")
      end
    end
  end 
end

-- Functions: TS2 Program Download 
function ts2_program_download(buffer, subtree)
	
  subtree:add(buffer(14,4), "unk:", buffer(14,4):uint())
  subtree:add_le(buffer(18,2), "unk:", buffer(18,2):le_uint())
  subtree:add_le(buffer(20,4), "timestamp:", os.date('%c',buffer(20,4):uint()))
  subtree:add(buffer(24,10), "project:", buffer(24,10):string())
  subtree:add_le(buffer(34,2), "func_counter:", buffer(34,2):le_uint())
  subtree:add_le(buffer(36,2), "program_counter:", buffer(36,2):le_uint())
  subtree:add_le(buffer(38,2), "unk:", buffer(38,2):le_uint())
 
end

-- Functions: Get TS2 data module version
function get_t2_data_module_version(buffer, subtree)
	
  chassis = subtree:add_le(buffer(14,1), "chassis:", buffer(14,1):le_uint())
  if buffer(15,1):le_uint() == 255 then  -- check if modles are present
  	buff = 8 -- bytes to read for each slots
  	buff_start = 16 -- buffer location
  	count = 0
  	while buff_start < 144 do
  		local module_type = buffer(buff_start,2):le_uint()
  		if module_type  ~= 0 then
  			slot = chassis:add_le(buffer(buff_start,8), "slot:"):append_text(" [" .. count .. "]")
  			local get_module_type = get_module_type(module_type)
  		
  			module_name = slot:add_le(ts_module, buffer(buff_start,2)):append_text("	[" .. get_module_type .. "] ")
  			slot:add_le(buffer(buff_start+2,2), "firmware_1:", buffer(buff_start+2,2):le_uint())
  			slot:add_le(buffer(buff_start+4,2), "firmware_2:", buffer(buff_start+4,2):le_uint())
  			slot:add_le(buffer(buff_start+6,2), "firmware_3:", buffer(buff_start+6,2):le_uint())
  		end
  		count = count + 1
  		buff_start = buff_start + buff
  	end	
  	
  	pib = subtree:add(buffer(144,17), "PIB")
  	pib:add(buffer(144,6), "assembly:", buffer(144,3):string(),"-",buffer(147,3):string())
  	pib:add(buffer(150,3), "revison:", buffer(150,3):string())
  	pib:add(buffer(153,8), "serial:", buffer(153,8):string())
  	controller = subtree:add(buffer(464,17), "Controller")
  	controller:add(buffer(464,6), "assembly:", buffer(464,3):string(),"-",buffer(467,3):string())
  	controller:add(buffer(470,3), "revison:", buffer(470,3):string())
  	controller:add(buffer(473,8), "serial:", buffer(473,8):string())
  	if ((buffer(12,2):le_uint() - 10) ~= 0) then
  		ts_raw = subtree:add(buffer(481,303),  "Data: " .. buffer(481,303))
    end
  else
  	chassis:append_text(" [ no modules attached ]")
  end
end

-- Function: Upload functions request
function upload_function_req(buffer, subtree)
	
  subtree:add_le(buffer(14,2), "func_id:", buffer(14,2):le_uint())
  subtree:add_le(buffer(16,4), "fixed_values:", buffer(16,4):le_uint())
  subtree:add_le(buffer(20,2), "offset:", buffer(20,2):le_uint())
end

-- Function: Upload functions response
function upload_function_res(buffer, subtree)
	
  subtree:add_le(buffer(14,4), "func_id:", buffer(14,4):le_uint())
  subtree:add_le(buffer(18,2), "full_chunks:", buffer(18,2):le_uint())
  subtree:add_le(buffer(20,2), "offset:", buffer(20,2):le_uint())
  subtree:add_le(buffer(22,2), "function_blocks (4 bytes):", buffer(22,2):le_uint())
  blocks = (buffer(22,2):le_uint())
  buff = 24
  local count = 1
  p = 0
  ts_func = subtree:add(buffer(24, blocks),  "Functions: ", blocks)  -- split functions based on the blocks number
  while p < blocks-1 do
  	p = p + 1
  	function_hex = ts_func:add(ts_function, buffer(buff,4)):append_text("	[" .. count .. "]")
  	buff = buff + 4
    count = count + 1
    if (p+1 == blocks)  then
      crc32_value = ts_func:add(crc32, buffer(buff,4)):append_text(" (" .. buffer(buff,4):uint() .. ")")
    end
  end
end

-- Function: Upload program request
function upload_program_req(buffer, subtree)
	
  subtree:add_le(buffer(14,2), "program_id:", buffer(14,2):le_uint())
  subtree:add_le(buffer(16,4), "fixed_values:", buffer(16,4):le_uint())
  subtree:add_le(buffer(20,2), "offset:", buffer(20,2):le_uint())
end

-- Function: Upload program response
function upload_program_res(buffer, subtree)
	
  subtree:add_le(buffer(14,2), "program_id:", buffer(14,2):le_uint())
  subtree:add_le(buffer(18,2), "full_chunks:", buffer(18,2):le_uint())
  subtree:add_le(buffer(20,2), "offset:", buffer(20,2):le_uint())
  subtree:add_le(buffer(22,2), "program_blocks (4 bytes):", buffer(22,2):le_uint())
  id = buffer(14,2):le_uint()
  chunked = buffer(18,2):le_uint()
  blocks_num = buffer(22,2):le_uint()
  offset = buffer(20,2):le_uint()
  blocks = (buffer(22,2):le_uint())*4
  buff = 24
  local count = 1
  p = 0
  ts_prog = subtree:add(ts_full_program, buffer(24, blocks-8))  -- split programs based on the blocks number
	while p < blocks-8 do
  	p = p + 4
    program_hex = ts_prog:add(ts_program, buffer(buff,4)):append_text("	[" .. count .. "]")
  	buff = buff + 4
    count = count + 1
    if (p+4 == blocks)  then
      crc32_value = ts_prog:add(crc32, buffer(buff,4)):append_text(" (" .. buffer(buff,4):uint() .. ")")
    end
  end 
end

-- Function: Get chassis status response
function get_chassis_status_resp(buffer, subtree)  

  subtree:add(buffer(14,2), "TriNode:", buffer(14,2):le_uint())
  if buffer(17,1):le_uint() == 0 then
  	subtree:add(ts_cp_runState, buffer(17,1)):append_text("	[Running] ")
  elseif buffer(17,1):le_uint() == 1 then
  	subtree:add(ts_cp_runState, buffer(17,1)):append_text("	[Stop] ")
  elseif buffer(17,1):le_uint() == 2 then
  	subtree:add(ts_cp_runState, buffer(17,1)):append_text("	[Pause] ")
  end
  if buffer(18,1):uint() == 0 then
  	subtree:add(ts_cp_keyState, buffer(18,1)):append_text("	[Stop] ")
  elseif buffer(18,1):uint() == 1 then
  	subtree:add(ts_cp_keyState, buffer(18,1)):append_text("	[Program] ")
  elseif buffer(18,1):uint() == 2 then
  	subtree:add(ts_cp_keyState, buffer(18,1)):append_text("	[Run] ")
  elseif buffer(18,1):uint() == 3 then
  	subtree:add(ts_cp_keyState, buffer(18,1)):append_text("	[Remote] ")
  end
  subtree:add(buffer(20,2), "project_minor:", buffer(20,2):uint())
  subtree:add(buffer(22,2), "project_major:", buffer(22,2):uint())
  subtree:add(buffer(24,4), "project_timestamp:", buffer(24,4):uint())
  subtree:add(buffer(28,4), "scan_request:", buffer(28,4):uint()):append_text(" ms")
  subtree:add(buffer(32,4), "scan_actual:", buffer(32,4):uint()):append_text(" ms")
  subtree:add(buffer(36,2), "scan_surplus:", buffer(36,2):le_uint()):append_text(" ms")
  subtree:add(buffer(42,4), "poll_time:", buffer(42,4):le_uint()):append_text(" ms")
  subtree:add(buffer(46,10), "project:", buffer(46,10):string())
  subtree:add(buffer(56,4), "calendar:", os.date('%c',buffer(56,4):uint())) 
  subtree:add(buffer(64,4), "memory_max:", buffer(64,4):le_uint())
  subtree:add(buffer(68,4), "memory_free:", buffer(68,4):le_uint())
  -- Slots
  buff = 32 -- bytes to read for each slots
  buff_start = 180 -- buffer location
  count = 0
  while buff_start < 692 do
  	local module_type = buffer(buff_start+2,1):uint()
  	if module_type  ~= 0 then
  		slot = subtree:add(buffer(buff_start,32), "slot:"):append_text(" [" .. count .. "]")
  		local get_module_type = get_module_type(module_type)
  		
      leds = slot:add(buffer(buff_start,1), "LEDs_status:")  
      led_struct = tobits(buffer(buff_start,1):uint())  -- bit analsys for main LEDs status
      if buffer(buff_start,1):uint() > 2 then
        leds:add(buffer(buff_start,1), "PASS:"):append_text(" [" .. get_led_status(led_struct:sub(#led_struct)) .. "]")
        leds:add(buffer(buff_start,1), "FAULT:"):append_text(" [" .. get_led_status(led_struct:sub(#led_struct-1, #led_struct-1)) .. "]")
        leds:add(buffer(buff_start,1), "ACTIVE:"):append_text(" [" .. get_led_status(led_struct:sub(#led_struct-2, #led_struct-2)) .. "]")
      else
        leds:add(buffer(buff_start,1), "Unable to get LEDs status [ check if module is racked properly ]")
      end
  		if count == 0 then
  			module_name = slot:add_le(ts_module, buffer(buff_start+2,1)):append_text("	[ Main Processor A ] ")
  		elseif count == 1 then
  			module_name = slot:add_le(ts_module, buffer(buff_start+2,1)):append_text("	[ Main Processor B ] ")
  		elseif count == 2 then
  			module_name = slot:add_le(ts_module, buffer(buff_start+2,1)):append_text("	[ Main Processor C ] ")
  		else
  			module_name = slot:add_le(ts_module, buffer(buff_start+2,1)):append_text("	[" .. get_module_type .. "] ")
  		end
  		if buffer(buff_start+3,1):uint() == 1 then
  			slot:add(buffer(buff_start+3,1), "config_mismatch:", buffer(buff_start+3,1):uint()):append_text(" [Grey: project and hardware configuration are correct] ")
  		elseif buffer(buff_start+3,1):uint() == 2 then
  			slot:add(buffer(buff_start+3,1), "config_mismatch:", buffer(buff_start+3,1):uint()):append_text(" [Grey: MP configured in the project is not installed in slot] ")
  		elseif buffer(buff_start+3,1):uint() == 3 then
  			slot:add(buffer(buff_start+3,1), "config_mismatch:", buffer(buff_start+3,1):uint()):append_text(" [Blue: spare module is not installed] ")
  		elseif buffer(buff_start+3,1):uint() == 4 then
  			slot:add(buffer(buff_start+3,1), "config_mismatch:", buffer(buff_start+3,1):uint()):append_text(" [Red: module configured in the project is not installed in slot] ")
  		elseif buffer(buff_start+3,1):uint() == 5 then
  			slot:add(buffer(buff_start+3,1), "config_mismatch:", buffer(buff_start+3,1):uint()):append_text(" [Yellow: module installed in the slot is not configured in the project] ")
  		end
  		slot:add(buffer(buff_start+4,28), "padding")	
  	end
  	count = count + 1
  	buff_start = buff_start + buff
  end	
end


-- Function: Tricon attached
function tricon_attached(buffer, subtree)	
  if buffer(17,1):uint() == 0 then
  	if buffer(18,1):uint() == 0 then
  		subtree:add(buffer(17,2), "MP type:", buffer(17,2)):append_text(" Tricon v9 - 3008 Main Processor ")
  	else
  		subtree:add(buffer(17,2), "MP type:", buffer(17,2)):append_text("  unknown MP model  ")
  	end
  elseif buffer(17,1):uint() == 10 then
  	if buffer(18,1):le_uint() == 0 then
  		subtree:add(buffer(17,2), "MP type:", buffer(17,2)):append_text(" Tricon v10.0.x - 3008 Main Processor ")
  	elseif buffer(18,1):le_uint() == 1 then
  		subtree:add(buffer(17,2), "MP type:", buffer(17,2)):append_text(" Tricon v10.1.x - 3008 Main Processor ")
  	elseif buffer(18,1):le_uint() == 2 then
  		subtree:add(buffer(17,2), "MP type:", buffer(17,2)):append_text(" Tricon v10.2.x - 3008 Main Processor ")
  	elseif buffer(18,1):le_uint() == 3 then
  		subtree:add(buffer(17,2), "MP type:", buffer(17,2)):append_text(" Tricon v10.3.x - 3008 Main Processor ")
  	elseif buffer(18,1):le_uint() == 4 then
  		subtree:add(buffer(17,2), "MP type:", buffer(17,2)):append_text(" Tricon v10.4.x - 3008 Main Processor ")
  	else
  		subtree:add(buffer(17,2), "MP type:", buffer(17,2)):append_text(" Tricon v10.x.x - 3008 Main Processor ")
  	end
  else
  	subtree:add(buffer(17,2), "MP type:", buffer(17,2)):append_text("  unknown MP model  ")
  end 
end

-- Function: convert value to bit rappresentation
function tobits(num)
  local t={}
  while num>0 do
      rest=num%2
      t[#t+1]=rest
      num=(num-rest)/2
  end
  return string.reverse(table.concat(t))
end
-- Function: crc32 check_implant
function crc32_calc(chunk, id, p_buffer, block_num, offset, pinfo, sign)
  local payloads = {}
  local triton = false

  if pinfo.number <= pkt_max_number then
    if crc_table[pinfo.number] == nil then
      return 0, triton
    end
    return crc_table[pinfo.number].crc, crc_table[pinfo.number].mlw
  else  
    pkt_max_number = pinfo.number
  end

  local track = offset+block_num

  if not table.contains_key(pkt_table, id) then
    pkt_table[id] = { Payload = { } }
  end

  if track == chunk then
    table.insert(pkt_table[id].Payload, #pkt_table[id].Payload+1 , Struct.fromhex(Struct.tohex(p_buffer:sub(1, -9))))
    payloads = table.concat(pkt_table[id].Payload)
    pkt_table[id] = nil
    local checksum =  UInt64.lower((bit.bxor(UInt64.lower(CRC32(payloads)), 2068988371)))
    if checksum == sign then
      triton = true
    end
    crc_table[pinfo.number] = { crc = UInt64.lower(CRC32(payloads)) , mlw = triton }
    return crc_table[pinfo.number].crc, crc_table[pinfo.number].mlw
  else
    table.insert(pkt_table[id].Payload, #pkt_table[id].Payload+1 ,p_buffer)
    return 0
  end
end 

function table.contains_key(t, p)
  for key, _ in pairs(t) do
    if key == p then
      return true
    end
  end
  return false
end

local crc32_table
function CRC32(s,crc)

  if not crc32_table then
    crc32_table = {}
    for i=0,255 do
      local r=i
      for j=1,8 do
        r = bit.bxor(bit.rshift(r,1),bit.band(0xedb88320,bit.bnot(bit.band(r,1)-1)))
      end
      crc32_table[i] = r
    end
  end
  crc = bit.bnot(crc or 0)
  for i=1,#s do
    local c = s:byte(i)
    crc = bit.bxor(crc32_table[bit.band(bit.bxor(c,crc),0xff)],bit.rshift(crc,8))
  end
  return bit.bnot(crc)
end

function wlog(s) -- debugging function 
  file = io.open("/tmp/debug", "a")
  file:write("\n debug: ", s)
  file:flush()
end


local udp_port = DissectorTable.get("udp.port")
udp_port:add(1502, ts_proto)
