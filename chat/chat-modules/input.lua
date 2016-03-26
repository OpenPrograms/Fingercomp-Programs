addListener("glasses_chat_command", "input.input", function(evt, addr, user, uuid, msg)
  if users[user] then
    local active = users[user].currentTab
    local showTabUserdata = surfaces[user].objects["chat.text.chans." .. active].getUserdata()
    if showTabUserdata and showTabUserdata.chan then
      local chan = showTabUserdata.chan
      if msg:sub(1, 1) ~= "/" then
        sendMsgChan(chan, user, msg)
      end
    end
  end
end)

-- vim: expandtab tabstop=2 shiftwidth=2 :
