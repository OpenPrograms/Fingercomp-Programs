if not require("component").isAvailable("internet") then
  io.stderr:write("This program requires internet card.\n")
  return 1
end

print("Installing hpm...")
os.execute("pastebin run vf6upeAN")
print("Done.")
