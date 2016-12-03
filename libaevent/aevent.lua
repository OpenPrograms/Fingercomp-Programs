local meta = {
  __call = function (cls, incStdEvt)
    local self = setmetatable({}, {__index = cls})

    self.keys = {}
    self.priorities = {}
    self.maxPriority = 0

    -- Create a new listener for each engine
    self.eventListener = function(e)
      return function(evt, ...)
        self:push(e({...}))
      end
    end

    return self
  end,
  __gc = function (self)
    if self.stdEvents and #self.stdEvents > 0 then
      local event = require("event")
      for _, name in pairs(self.stdEvents) do
        for _, listener in pairs(std.stdEvents[name]) do
          listener:destroy()
        end
      end
    end

    if self.timers and #self.timers > 0 then
      local event = require("event")
      for _, timer in pairs(self.timers) do
        timer:destroy()
      end
    end
  end
}
meta.__index = meta

return setmetatable({
  push = function (self, event)
    for _, i in pairs(self.keys) do
      local priority = self.priorities[i]

      if priority then
        for _, handler in ipairs(priority) do
          if handler.targets[event.name] then
            handler(event)

            if event.canceled or event.once then
              return
            end
          end
        end
      end
    end
  end,

  subscribe = function (self, name, id, handler)
    if id > self.maxPriority then
      self.maxPriority = id
    end

    local found = false
    for _, key in ipairs(self.keys) do
      if key == id then
        found = true
      end
    end

    if not found then
      table.insert(self.keys, id)
      table.sort(self.keys)
    end

    local priority = self.priorities[id]
    if not priority then
      self.priorities[id] = {}
      priority = self.priorities[id]
    end

    local pos = #priority + 1

    table.insert(priority, setmetatable({
      priority = id,
      destroy = function (hself)
        self.priorities[hself.priority][pos] = nil
      end,
      targets = {[name] = true}
    }, {
      __call = handler
    }))

    return self.priorities[id][pos]
  end,

  event = function (self, name)
    return setmetatable({}, {
      __call = function (cls, data, once)
        local inst = setmetatable({
          get = function (self)
            return self.data
          end,
          cancel = function (self)
            self.canceled = true
          end
        }, {
          __index = function (self, k)
            local v = rawget(cls, k)
            if v then
              return v
            else
              local v = rawget(self, k)
              return v and v or rawget(self.data, k)
            end
          end
        })

        inst.name = name
        inst.data = data
        inst.once = once or false
        inst.canceled = false

        return inst
      end
    })
  end,

  stdEvent = function (self, name, evt)
    local event = require("event")
    self.stdEvents = self.stdEvents or {}
    if self.stdEvents[name] then
      for _, hdlr in pairs(self.stdEvents[name]) do
        if hdlr.event == evt then
          return
        end
      end
    end
    self.stdEvents[name] = self.stdEvents[name] or {}
    local handler = self.eventListener(evt)
    local pos = #self.stdEvents[name] + 1
    table.insert(self.stdEvents[name], {
      name = name,
      event = evt,
      handler = handler,
      destroy = function (hself)
        event.ignore(hself.name, hself.handler)
        self.stdEvents[hself.name][pos] = nil
      end
    })
    event.listen(name, handler)
    return self.stdEvents[name][pos]
  end,

  timer = function (self, interval, e, times)
    local event = require("event")
    self.timers = self.timers or {}
    local timerFunction = function()
      self:push(e {
        time = os.time(),
        interval = interval
      })
    end
    local pos = #self.timers + 1

    local id = event.timer(interval, timerFunction, times)

    table.insert(self.timers, {
      interval = interval,
      event = e,
      handler = timerFunction,
      id = id,

      destroy = function (hself)
        event.cancel(hself.id)
        self.timers[pos] = nil
      end
    })

    return self.timers[pos]
  end
}, meta)
