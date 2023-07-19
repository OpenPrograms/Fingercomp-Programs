return function(_ENV)
  local json = dofile("third-party/json.lua/json.lua")

  local lib = {}

  lib.json = json

  function lib.makeWycheproofTests(args)
    local f =
      assert(io.open("third-party/wycheproof/testvectors/" .. args.file, "r"))
    local testJson = f:read("a")
    f:close()
    local tests = json.decode(testJson)

    for _, testGroup in ipairs(tests.testGroups) do
      local groupData = args.prepareGroupData and args.prepareGroupData(testGroup)

      if not args.groupFilter or args.groupFilter(testGroup, groupData) then
        context(args.groupName(testGroup, groupData), function()
          for _, testSpec in ipairs(testGroup.tests) do
            local testData =
              args.prepareTestData and args.prepareTestData(testSpec)

            if not args.testFilter or
                args.testFilter(testSpec, testGroup, testData, groupData) then
              local testName = ("test %d"):format(testSpec.tcId)

              if testSpec.comment ~= "" then
                testName = testName .. ": " .. testSpec.comment
              end

              test(testName, function()
                args.runTest(testSpec, testGroup, groupData, testData)
              end)
            end
          end
        end)
      end
    end
  end

  return lib
end
