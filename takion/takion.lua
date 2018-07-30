-- initial wireshark lua dissector for takion udp communication
-- Protobuff parts are not fully dissected - wireshark won't dissect parts nested in bytearray(string) wire
-- use protoc instead, works fine

local takion = Proto("takion","Gaikai takion protocol")
local mytype = ProtoField.uint8("takion.type", "Type")
local mytype2 = ProtoField.uint8("takion.subtype", "SubType")
takion.fields = {mytype, mytype2}
function takion.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "Takion"
    local subtree1 = tree:add(takion,buffer())
    local taktype = buffer(0,1)
    local maintype = taktype:bitfield(4,4)
    local subtype = taktype:bitfield(0,4)
    subtree1:add(mytype, taktype, maintype, "Type: " .. maintype)
    subtree1:add(mytype2, taktype, subtype, "subType: " .. subtype)
    local pos = 1

    if maintype == 2 then
        pinfo.cols.info:set("Video")
        subtree = subtree1:add(buffer(1,20),"Video")
        subtree:add(buffer(1,2),"PacketId: " .. buffer(1,2):uint())
        subtree:add(buffer(3,2),"FrameId: " .. buffer(3,2):uint())
        subtree:add(buffer(5,1),"lonely Byte: " .. buffer(5,1))

        local framepart = buffer(6,1)
        local partcount = buffer(7,1)
        subtree:add(framepart,"partNo: " .. framepart:bitfield(0,3) .. "/" .. partcount:bitfield(0,6))
        subtree:add(framepart,"remainder1: " .. framepart:bitfield(3,5))
        subtree:add(partcount,"remainder2: " .. partcount:bitfield(6,2))
        subtree:add(buffer(8,2),"sth: " .. buffer(8,2))
        subtree:add(buffer(10,4),"Crypto: " .. buffer(10,4))
        local incrementer = buffer(14,3)
        subtree:add(incrementer,"Sync: " .. incrementer:bitfield(0,20))
        subtree:add(incrementer,"remainder3: " .. incrementer:bitfield(20,4))
        subtree:add(buffer(17,4),"Sync?: " .. buffer(17,4))

        pos = 21
    end

    if maintype == 3 then
        pinfo.cols.info:set("Audio")
            subtree = subtree1:add(buffer(1,18),"Audio")
            subtree:add(buffer(1,2),"PacketId: " .. buffer(1,2):uint())
            subtree:add(buffer(3,2),"NextId: " .. buffer(3,2):uint())
        subtree:add(buffer(5,5),"SomeFlags: " .. buffer(5,5))

        subtree:add(buffer(10,4),"Crypto: " .. buffer(10,4))

        local incrementer = buffer(14,3)
        subtree:add(incrementer,"Sync: " .. incrementer:bitfield(0,20))

        local sequencer = buffer(17,1)
            subtree:add(incrementer,"?, ?: " .. incrementer:bitfield(20,4) .. ", " .. sequencer:bitfield(0,4))
            subtree:add(sequencer,"remainder: " .. sequencer:bitfield(4,4))
        subtree:add(buffer(18,1),"sth: " .. buffer(18,1))

        pos = 19
    end

    if maintype == 6 then
	    pinfo.cols.info:set("Feedback (state)")
    	subtree = subtree1:add(buffer(1,7),"Feedback (State)")
    	subtree:add(buffer(1,2),"AckId: " .. buffer(1,2):uint())
    	subtree:add(buffer(3,2),"Empty: " .. buffer(3,2))
	    subtree:add(buffer(5,2),"Incr?: " .. buffer(5,2))
	    subtree:add(buffer(7,1),"byte: " .. buffer(7,1))

	    pos = 8
    end

    if maintype == 5 then
        pinfo.cols.info:set("Congestion")
        subtree = subtree1:add(buffer(1,14),"Congestion")
        subtree:add(buffer(1,2),"Empty?: " .. buffer(1,2):uint())
        subtree:add(buffer(3,2),"Queue (>> 1?): " .. buffer(3,2))
        subtree:add(buffer(5,2),"Empty " .. buffer(5,2))
        subtree:add(buffer(7,4),"Crypto: " .. buffer(7,4))
        subtree:add(buffer(11,4),"Packets rcv: " .. buffer(11,4):bitfield(0,28))

        pos = 15
    end

    if maintype == 0 then
        pinfo.cols.info:set("Control")
        subtree = subtree1:add(buffer(1,16),"Control")
        subtree:add(buffer(1,4),"ReceiverId: " .. buffer(1,4))
        subtree:add(buffer(5,4),"Crypoto: " .. buffer(5,4))
        subtree:add(buffer(9,4),"Incr: " .. (buffer(9,4)))
        subtree:add(buffer(13,1),"Flag1: " .. buffer(13,1))
        subtree:add(buffer(14,1),"ProtoBuffFlag: " .. buffer(14,1))
        subtree:add(buffer(15,2),"PLoad Size: " .. buffer(15,2):uint())
        if buffer(15,2):uint() > 4 then
            subtree:add(buffer(17,4),"Func Incr: " .. buffer(17,4))
            subtree:add(buffer(21,4),"class(?): " .. buffer(21,4))
        end
        if buffer(14,1):uint() == 1 then
            local rawData = buffer(26)
            local protoDiss = Dissector.get("protobuf")
            protoDiss:call(rawData:tvb(), pinfo, subtree1)

        end
        pos = buffer:len()
    end

    if maintype == 8 then
        pinfo.cols.info:set("Client info")
        local rawData = buffer(1)
        local protoDiss = Dissector.get("protobuf")
        protoDiss:call(rawData:tvb(), pinfo, subtree1)
        pos = buffer:len()
    end

    if pos < buffer:len() then
        subtree1:add(buffer(pos),"RawData (" .. buffer(pos):len() .. "b):" .. buffer(pos))
    end

end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 9297 and 9296
udp_table:add(9297,takion)
udp_table:add(9296,takion)