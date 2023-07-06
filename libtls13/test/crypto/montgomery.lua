context(
  "Big integer arithmetic and modular exponentiation tests #crypto #montgomery",
  function()
    local montgomery = require("tls13.crypto.montgomery")

    context("64-by-32 division #div64by32", function()
      test("manual tests", function()
        assert.are.equal(
          0xffffffffffffffff >> 31,
          montgomery.__internal.divide64By32(0xffffffff, 0xffffffff, 0x80000000)
        )

        assert.are.equal(
          0x7fffffffffffffff // 0x8389235f,
          montgomery.__internal.divide64By32(0x7fffffff, 0xffffffff, 0x8389235f)
        )

        assert.are.equal(
          0x100000001,
          montgomery.__internal.divide64By32(0xffffffff, 0xffffffff, 0xffffffff)
        )

        assert.are.equal(
          0xdf2e4018,
          montgomery.__internal.divide64By32(0xb8691834, 0x71893752, 0xd3875292)
        )
      end)

      test("numbers from data/div64by32.txt", function()
        for line in io.lines("test/data/div64by32.txt") do
          local dividend, divisor, quotient =
            line:match("(0x%x+) (0x%x+) (0x%x+)")
          dividend = assert(tonumber(dividend))
          divisor = assert(tonumber(divisor))
          quotient = assert(tonumber(quotient))
          local hi, lo = dividend >> 32, dividend & 0xffffffff

          assert.are.equal(
            ("%x"):format(quotient),
            ("%x"):format(montgomery.__internal.divide64By32(hi, lo, divisor))
          )
        end
      end)
    end)

    test("big integer subtraction #subVecVecShifted", function()
      local minuend = montgomery.fromHex(
        "123456789abcdef0123456789abcdef0123456789abcdef0123456789bcdef"
      )
      assert.are.equal(0, montgomery.__internal.subVecVecShifted(
        minuend,
        montgomery.fromHex(
          "fedcab9876543210fedcab9876543210fedcab9876543210fedcab9876543"
        ),
        0
      ))
      assert.are.equal(
        "2468bbf13579bcf02468bbf13579bcf02468bbf13579bcf02468bbf1468ac",
        montgomery.toHex(minuend)
      )

      local minuend = montgomery.fromHex(
        "ad1a4ec55963e60f3dd1e9760cc91b61a81b40716d4091cceabddae2d9a86e3b\z
        182712b4742abf14eb407829fbaf7cb13d44017510eec2"
      )
      assert.are.equal(1, montgomery.__internal.subVecVecShifted(
        minuend,
        montgomery.fromHex("addbcf02468bbf13579bcf02468bbf"),
        10
      ))
      assert.are.equal(
        "ffff3e7fc312d826fbe6361a73c63d5c61a81b40716d4091cceabddae2d9a86e\z
        3b182712b4742abf14eb407829fbaf7cb13d44017510eec2",
        montgomery.toHex(minuend)
      )
    end)

    test("big integer remainder operation #modVecVec #long", function()
      for line in io.lines("test/data/mod-vec-vec.txt") do
        local x, y, remainder = line:match("(%x+) (%x+) (%x+)")
        x = montgomery.fromHex(x)
        y = montgomery.fromHex(y)
        remainder = montgomery.fromHex(remainder)

        assert.are.equal(
          montgomery.toHex(remainder),
          montgomery.toHex(montgomery.__internal.modVecVec(x, y))
        )
      end
    end)

    context("modular exponentiation #modpow", function()
      test("test case from num-bigint", function()
        local x = montgomery.fromHex(
          "efac3c0a0de55551fee0bfe467fa017a1a898fa16ca57cb1ca9e3248cacc09a9\z
          b99d6abc38418d0f82ae4238d9a68832aadec7c1ac5fed487a56a71b67ac59d5\z
          afb2802220d9592d247c4efcabbd9b75586088ee1dc00dc4232a8e156e8191dd\z
          675b6ae0c80f5164752940bc284b7cee885c1e10e495345b8fbe9cfde5233fe1\z
          19459d0bd64be53c27de5a02a829976b3309686282dad291bd38b6a9be396646\z
          ddaf8039a2573c391b14e8bc2cb53e48298c047ed9879e9c5a521076f0e27df3\z
          990e1659d3d8205b6443ebc09918ebee6764f6689f2b2be3b59cbc76d76d0dfc\z
          d737c3ec0ccf9c00ad0554bf17e776adb4edf9cc6ce540be762290935c53893b"
        )
        local y = montgomery.fromHex(
          "be0e6ea608746133e0fbc1bf82dba91ee2b56231a81888d2a833a1fcf7ff002a\z
          3c486a134f420bf3a5435be91a5c8391774d6e6c085d8357b0c97d4d2bb33f7c\z
          34c68059f78d2541eacc8832426f1816d3be001eb69f924251c7708ee10efe98\z
          449c9a4ab55a0f239d797410515da00d3ea079704478a2cac3d5043cbd9be1b4\z
          6dce479d4302d34484a939e60ab5ada712ae34b230cc473c9f8ee69d2cac5970\z
          29f5bf18bc8203e4f3e895a213c94f1e24c73d77e517e80153661fdda2ce9e47\z
          a73dd7f82f2adb1e3f136bf78ae5f3b808730de1a4eff678e77a06d019a522eb\z
          cbefba2a9caf7736b157c5c62d192591179468502ddb1822117b68a032f7db88"
        )
        local mod = montgomery.fromHex(
          "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\z
          020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437\z
          4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed\z
          ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05\z
          98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb\z
          9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b\z
          e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718\z
          3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff"
        )
        local result = montgomery.fromHex(
          "a14683116e56edc97a98228b5e9247760dd7836ecaabac13eda5373b4752aa65\z
          a145485040dc770e30aa86756be7d3a89d3085e4da5155cfb451ef6254d0da61\z
          cf2b2c87f495e096055309f777802bbb37271ba81313f1b5075c75d1024b6c77\z
          fdb56f17b05bce61e527ebfd2ee86860e9907066edd526e793d289bf6726b293\z
          41b0de24eff824248dfd374b4ec5954235ced2b26b195c9010042ffb8f58ce21\z
          bc10ec4264fda779d352d2343d4eaea6a86111ada37e955543ca78ce2885bed7\z
          5a30d182f1cf6834dc5b6e271a41ac34a2e91e1133363ff0f88a7b04900227c9\z
          f6e6d06b7856b4bb4e354d61060db6c8109c47356e7db4257b5d74c70b709508"
        )

        assert.are.equal(
          montgomery.toHex(result),
          montgomery.toHex(montgomery.modPowOdd(x, y, mod))
        )
      end)

      test("numbers from data/modpow.txt #long", function()
        for line in io.lines("test/data/modpow.txt") do
          local x, y, mod, result = line:match("(%x+) (%x+) (%x+) (%x+)")
          x = montgomery.fromHex(assert(x))
          y = montgomery.fromHex(assert(y))
          mod = montgomery.fromHex(assert(mod))
          result = montgomery.fromHex(assert(result))

          assert.are.equal(
            montgomery.toHex(result),
            montgomery.toHex(montgomery.modPowOdd(x, y, mod))
          )
        end
      end)
    end)
  end
)
