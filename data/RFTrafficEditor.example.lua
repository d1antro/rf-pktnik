log("example script up: chat (main 2) is logged, every 50th move summarised, packets counted per minute; say "
    .. "'!echo <text>' and the script injects <text> back as a chat line, '!upper' and for 30 s your 'hello' goes "
    .. "out as 'HELLO' (a patch rule: only while Rules is armed)")

local function printable(s)
  return (s:gsub("[^\32-\126]", "."))
end

local UPPER = "example: hello -> HELLO"
local upper_added = false
local upper_off = nil
local function upper()
  local ok, why
  if upper_added then
    ok, why = rules.enable(UPPER, true)
  else
    ok, why = rules.add{name = UPPER, dir = "C2S", main = 2,
                        action = {findHex = "68 65 6C 6C 6F", replaceHex = "48 45 4C 4C 4F"}}
    upper_added = ok and true or false
  end
  if not ok then
    log("upper: not on --", why)
    return
  end
  log("upper: on for 30 s" .. (why and " -- " .. why or rules.armed() and "" or " -- tick Rules (toolbar) to arm it"))
  if upper_off then cancel_tick(upper_off) end
  upper_off = after(30000, function()
    upper_off = nil
    log("upper: off", rules.enable(UPPER, false))
  end)
end

local seen = {C2S = 0, S2C = 0}
on_tick(60000, function()
  log(string.format("last minute: %d C2S / %d S2C packets", seen.C2S, seen.S2C))
  seen.C2S, seen.S2C = 0, 0
end)

local serial = 0
local moves = 0
on_packet(function(p)
  if p.tool then return end
  seen[p.dir] = seen[p.dir] + 1
  if p.dir == "C2S" and p.main == 4 and p.sub == 1 and p.status == "ok" then
    serial = p:field("dwSerial")
    moves = moves + 1
    if moves % 50 == 1 then
      log(string.format("move #%d: dwSerial %d at (%.1f, %.1f, %.1f)", moves, serial,
                        p:field("fCur[0]"), p:field("fCur[1]"), p:field("fCur[2]")))
    end
  elseif p.main == 2 then
    log(string.format("%s (%d,%d) %s %d B: %s", p.dir, p.main, p.sub,
                      p.name ~= "" and p.name or "unknown", p.size, printable(p.bytes:sub(1, 48))))
    local said = p.dir == "C2S" and p.sub == 2 and p.bytes:sub(2, 1 + (p:u8(0) or 0)) or ""
    local text = said:match("^!echo (.+)")
    if text then
      local msg = make("_chat_message_receipt_udp", {byMessageType = 1, dwSenderSerial = serial,
                       wszSenderName = "script", bySize = #text, wszChatData = text})
      log("echo:", inject_to_client(2, 10, msg:sub(1, 27 + #text)))
    elseif said:match("^!upper") then
      upper()
    end
  end
end)
