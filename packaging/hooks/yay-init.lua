-- TrustSight gate for yay.
--
-- Drop this file at ~/.config/yay/init.lua (or require it from an existing
-- init.lua).  AURPreInstall runs per package base after yay has cloned and
-- merged the AUR PKGBUILD and before sources are downloaded or built.
--
-- The gate is a hard gate: any refusal aborts the whole transaction.  yay
-- cannot drop one package from the transaction at this stage, and an AUR
-- package may be a pulled dependency of an approved one.
--
-- Emergency bypass: TRUSTSIGHT_GATE_DISABLE=1 (visible in the log).
-- Custom binary:   TRUSTSIGHT_GATE_BIN=/path/to/trustsight-gate
-- Dependency depth: TRUSTSIGHT_GATE_DEPTH=2 (default 1)

local function quote(value)
  return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function gate(event)
  if os.getenv("TRUSTSIGHT_GATE_DISABLE") == "1" then
    yay.log.warn("TrustSight gate disabled by TRUSTSIGHT_GATE_DISABLE=1")
    return
  end

  local parts = {
    quote(os.getenv("TRUSTSIGHT_GATE_BIN") or "trustsight-gate"),
    "--base", quote(event.match),
    "--dir", quote(event.data.dir),
    "--depth", quote(os.getenv("TRUSTSIGHT_GATE_DEPTH") or "1"),
  }
  for _, pkg in ipairs(event.data.packages) do
    table.insert(parts, quote(pkg.name))
  end

  local rc = os.execute(table.concat(parts, " "))
  -- gopher-lua follows Lua 5.1: 0 on success.  Accept `true` too so a
  -- runtime that follows 5.2 semantics cannot turn every approval into an
  -- abort.
  if not (rc == 0 or rc == true) then
    yay.abort("trustsight: " .. event.match .. " was not approved")
  end
end

yay.create_autocmd("AURPreInstall", {
  desc = "TrustSight per-package approval before sources/build",
  callback = function(event)
    gate(event)
  end,
})

-- Optional second check on the exact downloaded sources, after yay runs
-- `makepkg --verifysource`.  It uses the same per-package approval and is
-- useful when a recipe's pinning/checksum surface is the concern.
-- yay.create_autocmd("AURPostDownload", {
--   desc = "TrustSight re-check after verifysource",
--   callback = function(event)
--     gate(event)
--   end,
-- })
