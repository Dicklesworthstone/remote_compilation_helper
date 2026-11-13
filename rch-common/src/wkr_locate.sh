
rch_wkr_locate() {
    if [ -n "${RCH_WKR_BIN-}" ]; then
        if [ -f "$RCH_WKR_BIN" ] && [ -x "$RCH_WKR_BIN" ]; then RCH_WKR=$RCH_WKR_BIN; return 0; fi;
        RCH_WKR=; return 127;
    fi;
    for __rch_wkr_candidate in /usr/local/bin/rch-wkr "${HOME-}/.local/bin/rch-wkr" "${HOME-}/.local/bin/rch-wkr.exe"; do
        if [ -f "$__rch_wkr_candidate" ] && [ -x "$__rch_wkr_candidate" ]; then
            RCH_WKR=$__rch_wkr_candidate; return 0;
        fi;
    done;
    RCH_WKR=; return 127;
};
