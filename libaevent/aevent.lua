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
        table.remove(self.priorities[hself.priority], pos)
      end,
      targets = {[name] = true}
    }, {
      __call = handler
    }))
  end,

  event = function (self, name)
    return setmetatable({
      cancel = function (self)
        self.canceled = true
      end,

      get = function (self)
        return self.data
      end
    }, {
      __call = function (cls, data, once)
        local inst = setmetatable({}, {
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

  stdEvent = function (self, name)
    local event = require("event")
    table.insert(self.stdEvents, name)
    event.listen(name, self.eventListener)
  end
}, {
  __call = function (cls, incStdEvt)
    local self = setmetatable({}, {__index = cls})

    self.keys = {}
    self.priorities = {}
    self.maxPriority = 0

    -- Create a new listener for each engine
    self.eventListener = function(evt, ...)
      local e = self:event(evt)
      self:push(e(table.pack(...)))
    end

    return self
  end,
  __gc = function (self)
    if #self.stdEvents > 0 then
      local event = require("event")
      for name in self.stdEvents do
        event.ignore(name, self.eventListener)
      end
    end
  end
})
