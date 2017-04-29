drone = component.proxy(component.list("drone")())
modem = component.proxy(component.list("modem")())

ADDR = "16f260b2-b42a-4cd7-9cfe-e37e67524c55"

modem.open(1370)

while true do
  drone.setStatusText("Get\nBIOS...")
  modem.send(ADDR, 1370, "net-eeprom", "get bios")

  got = false
  code = ""

  while not got do
    e = {computer.pullSignal(1)}
    if e[1] == "modem_message" and e[3] and e[3]:sub(1, #ADDR) == ADDR and e[6] == "net-eeprom" and e[7] == "eeprom" and e[9] then
      got = e[8]
      code = code .. e[9]
    end
  end

  drone.setStatusText("Compile\ncode...")

  chunk, reason = load(code)
  if not chunk then
    modem.send(ADDR, 1370, "net-eeprom", "error", "compile", reason)
  else
    drone.setStatusText("Running")
    result = {xpcall(chunk, debug.traceback)}
    if result[1] then
      for k, v in pairs(result) do
        result[k] = tostring(v)
      end
      modem.send(ADDR, 1370, "net-eeprom", "success", table.unpack(result, 2, 7))
    else
      modem.send(ADDR, 1370, "net-eeprom", "error", "runtime", tostring(result[2]))
    end
  end
end
