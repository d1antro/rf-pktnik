#include "proto/decode.h"
#include "proto/packet_db.h"
#include "proto/packet_text.h"
#include <nlohmann/json.hpp>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace rfte;

static int g_fail = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_fail;                                                   \
        }                                                               \
    } while (0)
#define CHECK_STR(got, want)                                                                                           \
    do {                                                                                                               \
        const std::string g_ = (got), w_ = (want);                                                                     \
        if (g_ != w_) {                                                                                                \
            std::printf("FAIL %s:%d: %s\n  want: %s\n  got:  %s\n", __FILE__, __LINE__, #got, w_.c_str(), g_.c_str()); \
            ++g_fail;                                                                                                  \
        }                                                                                                              \
    } while (0)

static const Field* find_field(const Struct* s, const char* name) {
    if (!s) {
        return nullptr;
    }
    for (const Field& f : s->fields) {
        if (f.name == name) {
            return &f;
        }
    }
    return nullptr;
}

static void check_field(const PacketDb& db, const char* sname, const char* fname, const char* type, int count,
                        int offset, int size, const char* ref = "") {
    const Field* f = find_field(db.get(sname), fname);
    if (!f) {
        std::printf("FAIL: %s::%s missing\n", sname, fname);
        ++g_fail;
        return;
    }
    if (f->type != type || f->count != count || f->offset != offset || f->size != size || f->ref != ref) {
        std::printf("FAIL: %s::%s = %s[%d] @%d size %d ref '%s'\n", sname, fname, f->type.c_str(), f->count, f->offset,
                    f->size, f->ref.c_str());
        ++g_fail;
    }
}

static void check_struct(const PacketDb& db, const char* name, int size, bool var, int nfields) {
    const Struct* s = db.get(name);
    if (!s) {
        std::printf("FAIL: struct %s missing\n", name);
        ++g_fail;
        return;
    }
    if (s->size != size || s->var != var || (nfields >= 0 && (int)s->fields.size() != nfields)) {
        std::printf("FAIL: %s size %d var %d fields %d\n", name, s->size, (int)s->var, (int)s->fields.size());
        ++g_fail;
    }
}

static std::string lines(const Struct& s, const std::vector<uint8_t>& b) {
    std::string out;
    append_field_lines(out, map_fields(s, b.data(), b.size()));
    return out;
}

template <class T> static void put(std::vector<uint8_t>& b, T v) {
    const size_t at = b.size();
    b.resize(at + sizeof v);
    std::memcpy(b.data() + at, &v, sizeof v);
}

static std::string lines(const std::vector<FieldSpan>& sp) {
    std::string out;
    append_field_lines(out, sp);
    return out;
}

static PacketRec move_rec() {
    PacketRec r{};
    r.seq = 7;
    r.dir = Dir::C2S;
    r.main = 4;
    r.sub = 1;
    r.size = 22;
    r.edited = false;
    put(r.bytes, (uint8_t)1);
    put(r.bytes, 1.5f);
    put(r.bytes, -2.0f);
    put(r.bytes, 100.25f);
    put(r.bytes, (uint32_t)1234);
    put(r.bytes, (int16_t)-5);
    put(r.bytes, (int16_t)7);
    put(r.bytes, (uint8_t)3);
    return r;
}

static void test_db(const PacketDb& db, const char* real_path) {
    CHECK(db.struct_count() >= 1000);
    CHECK(db.opcode_count() >= 500);
    for (const Struct* s : db.all()) {
        int prev_off = -1, prev_end = 0;
        bool bad = false;
        for (const Field& f : s->fields) {
            if (f.type == "return") {
                bad = true;
            }
            if (f.offset < prev_off) {
                bad = true;
            }
            prev_off = f.offset;
            if (f.size >= 0) {
                if (f.offset < prev_end) {
                    bad = true;
                }
                prev_end = f.offset + f.size;
                if (s->size >= 0 && prev_end > s->size) {
                    bad = true;
                }
            }
            if (!f.ref.empty() && !db.get(f.ref)) {
                bad = true;
            }
        }
        if (bad) {
            std::printf("FAIL: invariant broken in %s\n", s->name.c_str());
            ++g_fail;
        }
    }

    check_struct(db, "_move_request_clzo", 22, false, 5);
    check_field(db, "_move_request_clzo", "byMoveType", "uint8_t", 1, 0, 1);
    check_field(db, "_move_request_clzo", "fCur", "float", 3, 1, 12);
    check_field(db, "_move_request_clzo", "dwSerial", "uint32_t", 1, 13, 4);
    check_field(db, "_move_request_clzo", "zTar", "int16_t", 2, 17, 4);
    check_field(db, "_move_request_clzo", "byDirect", "uint8_t", 1, 21, 1);

    check_struct(db, "_player_move_zocl", 17, false, 5);
    check_field(db, "_player_move_zocl", "dwSerial", "uint32_t", 1, 0, 4);
    check_field(db, "_player_move_zocl", "zCur", "int16_t", 3, 4, 6);
    check_field(db, "_player_move_zocl", "zTar", "int16_t", 2, 10, 4);
    check_field(db, "_player_move_zocl", "nAddSpeed", "int16_t", 1, 14, 2);
    check_field(db, "_player_move_zocl", "byDirect", "uint8_t", 1, 16, 1);

    check_struct(db, "_player_real_move_zocl", 33, false, 11);
    check_struct(db, "_player_fixpositon_zocl", 26, false, 8);

    check_struct(db, "_store_list_result_zocl", 1601, true, -1);
    check_field(db, "_store_list_result_zocl", "byStoreNum", "uint8_t", 1, 0, 1);
    check_field(db, "_store_list_result_zocl", "StorePos", "_store_list_result_zocl::_STORE_POS", 100, 1, 1600,
                "_store_list_result_zocl::_STORE_POS");
    check_struct(db, "_store_list_result_zocl::_STORE_POS", 16, false, -1);

    check_struct(db, "_base_download_result_zocl", 258, true, 29);
    {
        const Struct* s = db.get("_base_download_result_zocl");
        CHECK(s && !s->fields.empty() && s->fields[0].name == "byRetCode" && s->fields[0].offset == 0);
    }
    check_field(db, "_base_download_result_zocl", "EquipList", "_list_equip", 8, 0x47, 96,
                "_base_download_result_zocl::_list_equip");
    check_struct(db, "_base_download_result_zocl::_list_equip", 12, false, 5);
    check_field(db, "_base_download_result_zocl::_list_equip", "sTableCode", "char", 1, 0, 1);
    {
        const Field* f = find_field(db.get("_base_download_result_zocl"), "EmbellishList");
        CHECK(f && f->offset == 0xa7 && f->size == 77);
    }
    check_field(db, "_base_download_result_zocl", "dwGuildSerial", "uint32_t", 1, 0xf5, 4);
    {
        const Field* f = find_field(db.get("_base_download_result_zocl"), "byHonorGuildRank");
        CHECK(f && f->offset == 0x101);
    }

    check_struct(db, "_trans_ship_ticket_inform_zocl", 10, false, -1);
    check_field(db, "_trans_ship_ticket_inform_zocl", "dwNpcSerial", "uint32_t", 1, 0, 4);
    {
        const Field* f = find_field(db.get("_trans_ship_ticket_inform_zocl"), "TicketList");
        CHECK(f && f->count == 2 && f->offset == 4 && f->size == 6 &&
              f->ref == "_trans_ship_ticket_inform_zocl::_list");
    }

    check_struct(db, "_world_total_sales_check_time_acwr", 1, false, 0);
    check_struct(db, "_w_name", 17, false, 1);
    check_field(db, "_w_name", "name", "char", 17, 0, 17);

    PacketDb bad;
    std::string e;
    std::string missing = real_path;
    missing += ".does_not_exist.json";
    CHECK(!bad.load(missing, &e));
    CHECK_STR(e, "cannot open the file");
    CHECK(bad.struct_count() == 0);
    CHECK(bad.get("_w_name") == nullptr);
    std::printf("db: done\n");
}

static void check_cls(const PacketDb& db, Dir dir, uint8_t m, uint8_t s, uint16_t len, Status st, const char* name,
                      const char* label) {
    const Decoded d = db.classify(dir, m, s, len);
    if (d.status != st || d.name != name) {
        std::printf("FAIL: classify %s (%u,%u) len %u -> %s '%s'\n", dir_name(dir), m, s, len, status_name(d.status),
                    d.name.c_str());
        ++g_fail;
    }
    CHECK_STR(describe(d, len), label);
}

static void test_classify(const PacketDb& fx, const PacketDb& db) {
    {
        const Decoded d = fx.classify(Dir::S2C, 9, 1, 8);
        CHECK(d.status == Status::Ok && d.layout && d.layout->name == "_fix_a_zocl");
        CHECK((d.candidates == std::vector<std::string>{"_fix_a_zocl", "_fix_b_zocl", "_fix_var_zocl"}));
        CHECK((d.candidate_sizes == std::vector<int>{8, 2, 20}));
    }
    check_cls(fx, Dir::S2C, 9, 1, 8, Status::Ok, "_fix_a_zocl", "_fix_a_zocl ok");
    check_cls(fx, Dir::S2C, 9, 1, 2, Status::Ok, "_fix_b_zocl", "_fix_b_zocl ok");
    check_cls(fx, Dir::S2C, 9, 1, 20, Status::Ok, "_fix_var_zocl", "_fix_var_zocl ok");
    check_cls(fx, Dir::S2C, 9, 1, 5, Status::Var, "_fix_var_zocl", "_fix_var_zocl var(5/20)");
    check_cls(fx, Dir::S2C, 9, 1, 30, Status::Mismatch, "",
              "MISMATCH(30 fits none of: _fix_a_zocl 8, _fix_b_zocl 2, _fix_var_zocl 20)");
    CHECK(fx.classify(Dir::S2C, 9, 1, 30).layout == nullptr);
    check_cls(fx, Dir::C2S, 9, 1, 5, Status::Ok, "_fix_req_clzo", "_fix_req_clzo ok");
    check_cls(fx, Dir::C2S, 9, 1, 4, Status::Mismatch, "_fix_req_clzo", "_fix_req_clzo MISMATCH(4!=5)");
    CHECK(fx.classify(Dir::C2S, 9, 1, 4).layout == fx.get("_fix_req_clzo"));
    check_cls(fx, Dir::S2C, 9, 3, 4, Status::Unknown, "_fix_missing_zocl", "_fix_missing_zocl unknown(no layout)");
    CHECK(fx.classify(Dir::S2C, 9, 3, 4).layout == nullptr);
    check_cls(fx, Dir::S2C, 9, 9, 4, Status::Unknown, "", "unknown");
    CHECK(fx.classify(Dir::S2C, 9, 9, 4).candidates.empty());
    check_cls(fx, Dir::C2S, 9, 2, 12, Status::Unknown, "", "unknown");

    check_cls(db, Dir::C2S, 4, 1, 22, Status::Ok, "_move_request_clzo", "_move_request_clzo ok");
    check_cls(db, Dir::C2S, 4, 1, 21, Status::Mismatch, "_move_request_clzo", "_move_request_clzo MISMATCH(21!=22)");
    check_cls(db, Dir::S2C, 4, 4, 17, Status::Ok, "_player_move_zocl", "_player_move_zocl ok");
    check_cls(db, Dir::S2C, 4, 21, 33, Status::Ok, "_player_real_move_zocl", "_player_real_move_zocl ok");
    check_cls(db, Dir::S2C, 4, 9, 26, Status::Ok, "_player_fixpositon_zocl", "_player_fixpositon_zocl ok");
    check_cls(db, Dir::S2C, 12, 9, 49, Status::Var, "_store_list_result_zocl", "_store_list_result_zocl var(49/1601)");
    check_cls(db, Dir::S2C, 250, 250, 4, Status::Unknown, "", "unknown");
    std::printf("classify: done\n");
}

static void test_client(const PacketDb& fx, const PacketDb& db) {
    CHECK(!fx.has_client());
    CHECK(fx.client_arm_count() == 0 && fx.client_category_count() == 0 && fx.client_build().empty());
    CHECK(fx.client_route(9, 1).kind == ClientRoute::Kind::NoData);
    CHECK_STR(route_text(fx.client_route(9, 1), 9, 1), "");
    CHECK(db.has_client());
    CHECK_STR(db.client_build(), "2.2.3.2");
    CHECK(db.client_category_count() == 39);
    CHECK(db.client_arm_count() == 71);
    {
        const ClientRoute r = db.client_route(1, 9);
        CHECK(r.kind == ClientRoute::Kind::Arm && r.group == "system_msg" && !r.refused());
        CHECK(r.handler == "CNetworkMgr_SystemMsg_RegedCharResult_zone" && r.addr == 0x535a90 && r.bytes == 1264);
        CHECK_STR(route_text(r, 1, 9),
                  "client 2.2.3.2: system_msg (1,9) -> CNetworkMgr_SystemMsg_RegedCharResult_zone @0x535a90 (1264 B)");
    }
    {
        const ClientRoute r = db.client_route(20, 2);
        CHECK(r.kind == ClientRoute::Kind::Arm && r.handler == "unknown_libname_908" && r.addr == 0x5395c0 &&
              r.bytes == 13);
    }
    {
        const ClientRoute r = db.client_route(4, 4);
        CHECK(r.kind == ClientRoute::Kind::Processor && r.group == "CNetMsgProcessor_Position" && r.slot == 0 &&
              r.addr == 0x576360);
        CHECK_STR(route_text(r, 4, 4),
                  "client 2.2.3.2: (4,4) -> CNetMsgProcessor_Position::AnalysisServerPacket @0x576360 "
                  "(m_pMsgProcessor[0]) -- its sub switch is not mapped yet");
    }
    {
        const ClientRoute r = db.client_route(99, 1);
        CHECK(r.kind == ClientRoute::Kind::Processor && r.group == "CNetMsgProcessor_Apex" && r.slot == 36 &&
              r.addr == 0x57a820);
    }
    {
        const ClientRoute r = db.client_route(101, 0);
        CHECK(r.kind == ClientRoute::Kind::Ignored && !r.refused());
        CHECK_STR(route_text(r, 101, 0), "client 2.2.3.2: check_msg (101,0) -- accepted and ignored (returns 1)");
    }
    {
        const ClientRoute r = db.client_route(3, 17);
        CHECK(r.kind == ClientRoute::Kind::NoArm && r.group == "init_msg" && r.refused());
        CHECK_STR(
            route_text(r, 3, 17),
            "client 2.2.3.2: NO HANDLER for (3,17) -- init_msg has no arm for sub 17: \"Unknown Message\", returns 0");
    }
    {
        const ClientRoute r = db.client_route(250, 250);
        CHECK(r.kind == ClientRoute::Kind::NoCase && r.group.empty() && r.refused());
        CHECK_STR(route_text(r, 250, 250),
                  "client 2.2.3.2: NO HANDLER for (250,250) -- no case for main 250: \"Unknown Message\", returns 0");
        CHECK(route_on_host(r, ""));
        CHECK(route_on_host(r, "2.2.3.2"));
        CHECK(!route_on_host(r, "4.15"));
        CHECK_STR(route_text(r, 250, 250, "2.2.3.2"),
                  "client 2.2.3.2: NO HANDLER for (250,250) -- no case for main 250: \"Unknown Message\", returns 0");
        CHECK_STR(route_text(r, 250, 250, "4.15"),
                  "client 2.2.3.2: NO HANDLER for (250,250) -- no case for main 250: \"Unknown Message\", returns 0"
                  "  [2.2.3.2 reference -- this client is 4.15]");
        CHECK(!route_on_host(r, "4.55"));
        CHECK_STR(route_text(r, 250, 250, "4.55"),
                  "client 2.2.3.2: NO HANDLER for (250,250) -- no case for main 250: \"Unknown Message\", returns 0"
                  "  [2.2.3.2 reference -- this client is 4.55]");
        CHECK(!route_on_host(r, "EP1P2"));
        CHECK_STR(route_text(r, 250, 250, "EP1P2"),
                  "client 2.2.3.2: NO HANDLER for (250,250) -- no case for main 250: \"Unknown Message\", returns 0"
                  "  [2.2.3.2 reference -- this client is EP1P2]");
    }
    CHECK(route_on_host(fx.client_route(9, 1), "4.15"));
    CHECK_STR(route_text(fx.client_route(9, 1), 9, 1, "4.15"), "");
    CHECK(db.client_route(0, 0).kind == ClientRoute::Kind::NoCase);
    check_cls(db, Dir::S2C, 1, 9, 221, Status::Ok, "_reged_char_result_zone", "_reged_char_result_zone ok");
    check_cls(db, Dir::S2C, 1, 9, 152, Status::Var, "_reged_char_result_zone", "_reged_char_result_zone var(152/221)");
    check_cls(db, Dir::S2C, 1, 15, 14, Status::Ok, "_sel_char_result_zone", "_sel_char_result_zone ok");
    check_cls(db, Dir::S2C, 1, 2, 3, Status::Ok, "_enter_world_result_zone", "_enter_world_result_zone ok");
    check_cls(db, Dir::S2C, 1, 21, 70, Status::Var, "_not_arranged_char_inform_zocl",
              "_not_arranged_char_inform_zocl var(70/3451)");
    check_cls(db, Dir::S2C, 3, 6, 2103, Status::Ok, "_inven_download_result_zocl", "_inven_download_result_zocl ok");
    check_cls(db, Dir::S2C, 3, 24, 7, Status::Ok, "_monster_destroy_zocl", "_monster_destroy_zocl ok");
    check_cls(db, Dir::S2C, 3, 24, 202, Status::Ok, "_storage_refresh_inform_zocl", "_storage_refresh_inform_zocl ok");
    check_cls(db, Dir::S2C, 1, 8, 3451, Status::Unknown, "", "unknown");
    {
        const Decoded d = db.classify(Dir::C2S, 7, 9, 0);
        CHECK(d.name == "_equip_part_request_clzo" && d.candidates.size() == 1);
    }
    std::printf("client: done\n");
}

static void test_fields(const PacketDb& fx, const PacketDb& db) {
    const Struct* a = fx.get("_fix_a_zocl");
    const Struct* v = fx.get("_fix_var_zocl");
    const Struct* nest = fx.get("_fix_nest_zocl");
    const Struct* req = fx.get("_fix_req_clzo");
    const Struct* raw = fx.get("_fix_raw_zocl");
    const Struct* arr = fx.get("_fix_arr_zocl");
    CHECK(a && v && nest && req && raw && arr);
    if (!(a && v && nest && req && raw && arr)) {
        return;
    }

    CHECK_STR(lines(*a, {0xD2, 0x04, 0x00, 0x00, 0x05, 0x00, 0xFB, 0xFF}), "      +0000 uint32_t dwA = 1234 (0x4D2)\n"
                                                                           "      +0004 uint16_t wB = 5\n"
                                                                           "      +0006 int16_t zC = -5\n");
    CHECK_STR(lines(*a, {}), "      +0000 uint32_t dwA = <absent>\n"
                             "      +0004 uint16_t wB = <absent>\n"
                             "      +0006 int16_t zC = <absent>\n");
    CHECK_STR(lines(*v, {0x03, 0x61, 0x62, 0x00, 0x78}), "      +0000 uint8_t byNum = 3\n"
                                                         "      +0001 char szText[19] = \"ab\" (truncated 4/19)\n");
    {
        std::vector<uint8_t> b = {0x01, 0x41, 0x22, 0x5C, 0x0A, 0xC8, 0x00};
        b.resize(20, 0);
        const std::vector<FieldSpan> sp = map_fields(*v, b.data(), b.size());
        CHECK(sp.size() == 2);
        if (sp.size() == 2) {
            CHECK_STR(sp[1].value, "\"A\\\"\\\\\\x0A\\xC8\"");
        }
    }
    {
        const std::vector<uint8_t> b = {0x00, 0xAA, 0x01, 0x02, 0x03, 0x04, 0x05,
                                        0x06, 0x07, 0x08, 0xBB, 0xCC, 0xDD, 0xEE};
        const std::vector<FieldSpan> sp = map_fields(*nest, b.data(), b.size());
        using K = FieldSpan::Kind;
        const K kinds[] = {K::Field, K::Gap, K::Field, K::Gap, K::Extra};
        const int offs[] = {0, 1, 2, 10, 12}, sizes[] = {1, 1, 8, 2, 2};
        CHECK(sp.size() == 5);
        for (size_t i = 0; i < sp.size() && i < 5; ++i) {
            CHECK(sp[i].kind == kinds[i] && sp[i].offset == offs[i] && sp[i].size == sizes[i] &&
                  sp[i].avail == sizes[i]);
        }
        CHECK_STR(lines(*nest, b), "      +0000 uint8_t byRet = 0\n"
                                   "      +0001 (unmapped) = <1 B: AA>\n"
                                   "      +0002 _item List[2] = <8 B: 01 02 03 04 05 06 07 08>\n"
                                   "      +000A (unmapped) = <2 B: BB CC>\n"
                                   "      +000C (beyond sizeof) = <2 B: DD EE>\n");
        const Struct* ie = fx.get("_fix_nest_zocl::_item");
        CHECK(ie != nullptr);
        if (ie && sp.size() == 5) {
            CHECK_STR(lines(map_element(*ie, sp[2], 0, b.data(), b.size())),
                      "      +0002 uint16_t wIndex = 513 (0x201)\n"
                      "      +0004 uint16_t wNum = 1027 (0x403)\n");
            CHECK_STR(lines(map_element(*ie, sp[2], 1, b.data(), b.size())),
                      "      +0006 uint16_t wIndex = 1541 (0x605)\n"
                      "      +0008 uint16_t wNum = 2055 (0x807)\n");
            CHECK(map_element(*ie, sp[2], 2, b.data(), b.size()).empty());
            CHECK(map_element(*ie, sp[2], -1, b.data(), b.size()).empty());
            CHECK(map_element(*ie, sp[1], 0, b.data(), b.size()).empty());
            const std::vector<FieldSpan> t = map_element(*ie, sp[2], 1, b.data(), 7);
            CHECK(t.size() == 2);
            if (t.size() == 2) {
                CHECK(t[0].offset == 6 && t[0].avail == 1);
                CHECK(t[1].offset == 8 && t[1].avail == 0);
            }
            CHECK_STR(lines(t), "      +0006 uint16_t wIndex = <truncated 1/2: 05>\n"
                                "      +0008 uint16_t wNum = <absent>\n");
        }
    }
    CHECK_STR(lines(*req, {0x01, 0x00, 0x00}), "      +0000 bool bOn = true\n"
                                               "      +0001 float fX = <truncated 2/4: 00 00>\n");
    {
        std::vector<uint8_t> b = {0x02};
        put(b, 1.5f);
        CHECK_STR(lines(*req, b), "      +0000 bool bOn = true (0x02)\n"
                                  "      +0001 float fX = 1.5\n");
    }
    CHECK_STR(lines(*raw, {0x01, 0x00, 0x02, 0x00, 0x00, 0x00}), "      +0000 _CLID id = <6 B: 01 00 02 00 00 00>\n");
    {
        std::vector<uint8_t> b;
        for (int i = 0; i < 20; ++i) {
            b.push_back((uint8_t)i);
        }
        const std::vector<FieldSpan> sp = map_fields(*arr, b.data(), b.size());
        CHECK(sp.size() == 1);
        if (sp.size() == 1) {
            CHECK_STR(sp[0].value, "[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, ... (+4)]");
        }
    }

    if (const Struct* le = db.get("_base_download_result_zocl::_list_equip")) {
        std::vector<uint8_t> b(12, 0);
        b[0] = 0xFF;
        const std::string l = lines(*le, b);
        CHECK_STR(l.substr(0, l.find('\n') + 1), "      +0000 char sTableCode = -1\n");
    } else {
        CHECK(!"_base_download_result_zocl::_list_equip missing");
    }
    if (const Struct* bd = db.get("_base_download_result_zocl")) {
        const std::vector<uint8_t> b(258, 0xFF);
        const std::vector<FieldSpan> sp = map_fields(*bd, b.data(), b.size());
        CHECK(sp.size() == 29);
        bool all_fields = true, saw_equip = false, saw_guild = false;
        for (const FieldSpan& s : sp) {
            if (s.kind != FieldSpan::Kind::Field) {
                all_fields = false;
                continue;
            }
            if (s.field->name == "EquipList") {
                saw_equip = true;
                CHECK(s.offset == 0x47 && s.size == 96 && s.avail == 96);
                CHECK_STR(s.value, "<96 B: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF ...>");
            }
            if (s.field->name == "dwGuildSerial") {
                saw_guild = true;
                CHECK_STR(s.value, "4294967295 (0xFFFFFFFF)");
            }
        }
        CHECK(all_fields && saw_equip && saw_guild);
        const Struct* le = db.get("_base_download_result_zocl::_list_equip");
        const Struct* lm = db.get("_base_download_result_zocl::_list_embellish");
        CHECK(le && lm);
        for (const FieldSpan& s : sp) {
            if (s.kind != FieldSpan::Kind::Field) {
                continue;
            }
            if (le && s.field->name == "EquipList") {
                const std::vector<FieldSpan> e = map_element(*le, s, 7, b.data(), b.size());
                CHECK(e.size() == 5);
                if (e.size() == 5) {
                    CHECK(e[0].offset == 0x47 + 7 * 12 && e[0].field->name == "sTableCode");
                    CHECK(e[4].offset == 155 + 8 && e[4].field->name == "dwT");
                    CHECK_STR(e[4].value, "4294967295 (0xFFFFFFFF)");
                }
                CHECK(map_element(*le, s, 8, b.data(), b.size()).empty());
            }
            if (lm && s.field->name == "EmbellishList") {
                const std::vector<FieldSpan> e = map_element(*lm, s, 6, b.data(), b.size());
                CHECK(e.size() == 6);
                if (!e.empty()) {
                    CHECK(e[0].offset == 0xA7 + 6 * 11);
                }
            }
        }
    } else {
        CHECK(!"_base_download_result_zocl missing");
    }
    {
        const PacketRec r = move_rec();
        CHECK(r.bytes.size() == 22);
        const Decoded d = db.classify(r.dir, r.main, r.sub, r.size);
        CHECK_STR(format_packet(r, 1.5, describe(d, r.size), d.layout),
                  "#7 t+1.500ms C2S (4,1) size=22 _move_request_clzo ok\n"
                  "      +0000 uint8_t byMoveType = 1\n"
                  "      +0001 float fCur[3] = [1.5, -2, 100.25]\n"
                  "      +000D uint32_t dwSerial = 1234 (0x4D2)\n"
                  "      +0011 int16_t zTar[2] = [-5, 7]\n"
                  "      +0015 uint8_t byDirect = 3\n"
                  "    0000  01 00 00 C0 3F 00 00 00 C0 00 80 C8 42 D2 04 00\n"
                  "    0010  00 FB FF 07 00 03\n");
    }
    std::printf("fields: done\n");
}

static void test_copy(const PacketDb& fx, const PacketDb& db) {
    CHECK_STR(hex_line(nullptr, 0), "");
    {
        const uint8_t one = 0x0A;
        CHECK_STR(hex_line(&one, 1), "0A");
    }
    {
        const PacketRec r = move_rec();
        CHECK_STR(hex_line(r.bytes.data(), r.bytes.size()),
                  "01 00 00 C0 3F 00 00 00 C0 00 80 C8 42 D2 04 00 00 FB FF 07 00 03");
        const Decoded d = db.classify(r.dir, r.main, r.sub, r.size);
        CHECK_STR(
            format_snippet(r, describe(d, r.size), d.layout),
            "// #7 C2S (4,1) size=22 _move_request_clzo ok\n"
            "//   +0000 uint8_t byMoveType = 1\n"
            "//   +0001 float fCur[3] = [1.5, -2, 100.25]\n"
            "//   +000D uint32_t dwSerial = 1234 (0x4D2)\n"
            "//   +0011 int16_t zTar[2] = [-5, 7]\n"
            "//   +0015 uint8_t byDirect = 3\n"
            "const uint8_t byType[2] = { 4, 1 };\n"
            "const uint8_t msg[22] = {\n"
            "    0x01, 0x00, 0x00, 0xC0, 0x3F, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x80, 0xC8, 0x42, 0xD2, 0x04, 0x00,\n"
            "    0x00, 0xFB, 0xFF, 0x07, 0x00, 0x03,\n"
            "};\n"
            "CNetworkMgr__SendNetMessage(pThis, dwClientIndex, byType, (void*)msg, 22, nNetProcessIdx);\n");
    }
    {
        PacketRec r{};
        r.seq = 5;
        r.dir = Dir::S2C;
        r.main = 9;
        r.sub = 2;
        r.size = 14;
        r.bytes = {0x00, 0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xBB, 0xCC, 0xDD, 0xEE};
        CHECK_STR(format_snippet(r, "_fix_nest_zocl MISMATCH(14!=12)", fx.get("_fix_nest_zocl")),
                  "// #5 S2C (9,2) size=14 _fix_nest_zocl MISMATCH(14!=12)\n"
                  "//   +0000 uint8_t byRet = 0\n"
                  "//   +0001 (unmapped) = <1 B: AA>\n"
                  "//   +0002 _item List[2] = <8 B: 01 02 03 04 05 06 07 08>\n"
                  "//   +000A (unmapped) = <2 B: BB CC>\n"
                  "//   +000C (beyond sizeof) = <2 B: DD EE>\n"
                  "const uint8_t msg[14] = {\n"
                  "    0x00, 0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xBB, 0xCC, 0xDD, 0xEE,\n"
                  "};\n"
                  "_MSG_HEADER hdr = { 4 + 14, { 9, 2 } };\n"
                  "CNetworkMgr__AnalysisZoneServerPacket(pThis, &hdr, (void*)msg);\n");
    }
    {
        PacketRec r{};
        r.seq = 0;
        r.dir = Dir::S2C;
        r.main = 4;
        r.sub = 4;
        r.size = 2;
        r.bytes = {0x01, 0x02};
        CHECK_STR(format_snippet(r), "// #0 S2C (4,4) size=2\nconst uint8_t msg[2] = {\n    0x01, 0x02,\n};\n"
                                     "_MSG_HEADER hdr = { 4 + 2, { 4, 4 } };\n"
                                     "CNetworkMgr__AnalysisZoneServerPacket(pThis, &hdr, (void*)msg);\n");
    }
    {
        PacketRec r{};
        r.seq = 3;
        r.dir = Dir::C2S;
        r.main = 1;
        r.sub = 2;
        r.size = 0;
        r.edited = true;
        CHECK_STR(format_snippet(r),
                  "// #3 C2S (1,2) size=0 edited\nconst uint8_t byType[2] = { 1, 2 };\n"
                  "CNetworkMgr__SendNetMessage(pThis, dwClientIndex, byType, nullptr, 0, nNetProcessIdx);\n");
    }
    {
        PacketRec r{};
        r.seq = 9;
        r.dir = Dir::S2C;
        r.main = 12;
        r.sub = 9;
        r.size = 5000;
        r.bytes = {0xAA, 0xBB, 0xCC};
        CHECK_STR(format_snippet(r), "// #9 S2C (12,9) size=5000 captured=3\n"
                                     "// msg is the captured prefix only (3 of 5000 bytes) -- not the whole packet\n"
                                     "const uint8_t msg[3] = {\n    0xAA, 0xBB, 0xCC,\n};\n"
                                     "_MSG_HEADER hdr = { 4 + 3, { 12, 9 } };\n"
                                     "CNetworkMgr__AnalysisZoneServerPacket(pThis, &hdr, (void*)msg);\n");
    }
    std::printf("copy: done\n");
}

static void test_server(const PacketDb& db, const char* real_path) {
    struct Ok {
        uint8_t m, s;
        uint16_t len;
        const char* name;
    };

    const Ok oks[] = {
        {1, 1, 58, "_enter_world_request_zone"},        {1, 6, 1, "_moveout_user_request_zone"},
        {1, 10, 28, "_add_char_request_zone"},          {1, 14, 1, "_sel_char_request_zone"},
        {2, 10, 1, "_chat_map_recv_yesorno_clzo"},      {3, 1, 1, "_new_pos_start_request_clzo"},
        {3, 30, 4, "_other_shape_request_clzo"},        {4, 31, 1, "_move_type_change_request_clzo"},
        {7, 7, 11, "_use_potion_request_clzo"},         {13, 30, 1, "_party_req_block_report_clzo"},
        {14, 20, 1, "_pt_automine_selectore_clzo"},     {99, 1, 4, "_apex_msg_chcstart_return_clzo"},
        {98, 3, 342, "_hs_msg_make_guid_ack_msg_clzo"},
    };
    for (const Ok& o : oks) {
        check_cls(db, Dir::C2S, o.m, o.s, o.len, Status::Ok, o.name, (std::string(o.name) + " ok").c_str());
        if (db.classify(Dir::C2S, o.m, o.s, 0).candidates.size() != 1) {
            std::printf("FAIL: C2S (%u,%u) has %zu candidates\n", o.m, o.s,
                        db.classify(Dir::C2S, o.m, o.s, 0).candidates.size());
            ++g_fail;
        }
    }
    check_cls(db, Dir::C2S, 3, 3, 0, Status::Trigger, "CNetworkEX::BaseDownloadRequest",
              "CNetworkEX::BaseDownloadRequest trigger");
    check_cls(db, Dir::C2S, 1, 8, 0, Status::Trigger, "CNetworkEX::RegedCharRequest",
              "CNetworkEX::RegedCharRequest trigger");
    check_cls(db, Dir::C2S, 27, 56, 1, Status::Trigger, "CNetworkEX::GuildBattleJoinGuildBattleRequest",
              "CNetworkEX::GuildBattleJoinGuildBattleRequest trigger");
    check_cls(db, Dir::C2S, 31, 16, 5, Status::Unknown, "", "unknown");
    CHECK(db.classify(Dir::C2S, 31, 16, 5).candidates.empty());

    std::ifstream f(real_path);
    const nlohmann::json j = nlohmann::json::parse(f, nullptr, false);
    CHECK(!j.is_discarded() && j.contains("server"));
    if (j.is_discarded() || !j.contains("server")) {
        std::printf("server: done\n");
        return;
    }
    const nlohmann::json& sv = j.at("server");
    const nlohmann::json cats = sv.value("categories", nlohmann::json::array());
    const nlohmann::json arms = sv.value("arms", nlohmann::json::array());
    auto cat = [&](int m) -> nlohmann::json {
        for (const auto& c : cats) {
            if (c.value("main", -1) == m) {
                return c;
            }
        }
        return nlohmann::json::object();
    };
    auto arm = [&](int m, int s) -> nlohmann::json {
        for (const auto& a : arms) {
            if (a.value("main", -1) == m && a.value("sub", -1) == s) {
                return a;
            }
        }
        return nlohmann::json::object();
    };
    const std::string S;
    CHECK_STR(sv.value("function", S), "CNetworkEX::ClientLineAnalysis @0x1401dbb40");
    CHECK(cats.size() == 35);
    CHECK(arms.size() == 300);
    size_t with_struct = 0;
    for (const auto& a : arms) {
        if (a.contains("struct")) {
            ++with_struct;
        }
    }
    CHECK(with_struct >= 230);

    CHECK_STR(cat(1).value("kind", S), "switch");
    CHECK_STR(cat(1).value("default", S), "refused");
    CHECK_STR(cat(35).value("default", S), "accepted");
    CHECK_STR(cat(98).value("kind", S), "any");
    CHECK_STR(cat(98).value("handler", S), "CNationSettingManager::RecvGameGuardData");

    CHECK_STR(arm(1, 1).value("handler", S), "CNetworkEX::EnterWorldRequest");
    CHECK_STR(arm(1, 1).value("struct", S), "_enter_world_request_zone");
    CHECK_STR(arm(1, 1).value("via", S), "dispatch");
    CHECK_STR(arm(3, 1).value("struct", S), "_new_pos_start_request_clzo");
    CHECK_STR(arm(3, 1).value("via", S), "handler");
    CHECK_STR(arm(3, 3).value("handler", S), "CNetworkEX::BaseDownloadRequest");
    CHECK(!arm(3, 3).contains("struct"));
    CHECK_STR(arm(1, 8).value("handler", S), "CNetworkEX::RegedCharRequest");
    CHECK(!arm(1, 8).contains("struct"));
    CHECK_STR(arm(14, 20).value("handler", S), "AutoMineMachineMng::SelectOreType");
    CHECK_STR(arm(56, 1).value("handler", S), "PatriarchElectProcessor::Doit(_eRequestCandidateList)");
    CHECK(arm(27, 56).contains("note"));
    CHECK(!arm(27, 56).contains("struct"));

    const nlohmann::json ops = j.value("opcodes", nlohmann::json::array());
    auto has_clzo = [&](int m, int s, const std::string& st) {
        for (const auto& o : ops) {
            if (o.value("dir", S) == "clzo" && o.value("main", -1) == m && o.value("sub", -1) == s &&
                o.value("struct", S) == st) {
                return true;
            }
        }
        return false;
    };
    for (const auto& a : arms) {
        if (!a.contains("struct")) {
            continue;
        }
        const std::string st = a.value("struct", S);
        const int m = a.value("main", -1), s = a.value("sub", -1);
        if (!db.get(st)) {
            std::printf("FAIL: server arm (%d,%d) %s has no layout\n", m, s, st.c_str());
            ++g_fail;
        }
        if (!has_clzo(m, s, st)) {
            std::printf("FAIL: server arm (%d,%d) %s has no clzo row\n", m, s, st.c_str());
            ++g_fail;
        }
    }
    const nlohmann::json dropped = sv.value("dropped", nlohmann::json::array());
    CHECK(dropped.size() == 1);
    if (dropped.size() == 1) {
        CHECK(dropped[0].value("main", -1) == 31 && dropped[0].value("sub", -1) == 16);
        CHECK_STR(dropped[0].value("struct", S), "_buddy_del_result_clzo");
    }
    size_t nclzo = 0;
    for (const auto& o : ops) {
        if (o.value("dir", S) != "clzo") {
            continue;
        }
        ++nclzo;
        const std::string tag = o.value("server", S);
        if (tag != "arm" && tag != "any") {
            std::printf("FAIL: clzo (%d,%d) %s tagged '%s'\n", o.value("main", -1), o.value("sub", -1),
                        o.value("struct", S).c_str(), tag.c_str());
            ++g_fail;
        }
    }
    CHECK(nclzo >= 249);
    const nlohmann::json counts = j.value("meta", nlohmann::json::object()).value("counts", nlohmann::json::object());
    CHECK(counts.value("server_arms", -1) == 300);
    CHECK(counts.value("clzo_mappings", -1) >= 249);

    CHECK_STR(sv.value("build", S), "2.2.3.2");
    const nlohmann::json internal = sv.value("internal", nlohmann::json::object());
    CHECK(internal.value("above", -1) == 100);
    CHECK_STR(internal.value("handler", S), "CNetProcess::_InternalPacketProcess");
    CHECK_STR(arm(3, 3).value("payload", S), "unread");
    CHECK_STR(arm(27, 56).value("payload", S), "unread");
    CHECK_STR(arm(1, 6).value("payload", S), "unread");
    CHECK_STR(arm(56, 4).value("payload", S), "forwarded");
    CHECK_STR(arm(99, 2).value("payload", S), "forwarded");
    CHECK_STR(arm(14, 21).value("payload", S), "forwarded");
    for (const auto& a : arms) {
        const std::string pl = a.value("payload", S);
        const bool ok = a.contains("struct") ? !a.contains("payload") : (pl == "unread" || pl == "forwarded");
        if (!ok) {
            std::printf("FAIL: server arm (%d,%d) struct=%d payload '%s'\n", a.value("main", -1), a.value("sub", -1),
                        (int)a.contains("struct"), pl.c_str());
            ++g_fail;
        }
    }
    CHECK(counts.value("server_triggers", -1) == 44);
    CHECK(counts.value("server_forwarded", -1) == 9);
    std::printf("server: done\n");
}

static void check_route(const ServerRoute& r, ServerRoute::Kind kind, uint8_t m, uint8_t s, const char* text) {
    if (r.kind != kind) {
        std::printf("FAIL: server_route (%u,%u) kind %d, want %d\n", m, s, (int)r.kind, (int)kind);
        ++g_fail;
    }
    CHECK_STR(server_text(r, m, s), text);
}

static void test_server_route(const PacketDb& fx, const PacketDb& db) {
    using K = ServerRoute::Kind;
    using P = ServerRoute::Payload;
    CHECK_STR(status_name(Status::Trigger), "trigger");
    CHECK(kStatusCount == 5);
    CHECK(!fx.has_server());
    CHECK(fx.server_category_count() == 0 && fx.server_arm_count() == 0 && fx.server_trigger_count() == 0);
    CHECK_STR(fx.server_build(), "");
    CHECK(fx.server_route(9, 2).kind == K::NoData);
    CHECK_STR(server_text(fx.server_route(9, 2), 9, 2), "");
    CHECK_STR(server_text(fx.server_route(9, 2), 9, 2, "4.15"), "");
    CHECK(route_on_host(fx.server_route(9, 2), "4.15"));
    check_cls(fx, Dir::C2S, 9, 2, 12, Status::Unknown, "", "unknown");

    CHECK(db.has_server());
    CHECK_STR(db.server_build(), "2.2.3.2");
    CHECK(db.server_category_count() == 35);
    CHECK(db.server_arm_count() == 300);
    CHECK(db.server_trigger_count() == 44);

    const ServerRoute r41 = db.server_route(4, 1);
    check_route(r41, K::Arm, 4, 1, "server 2.2.3.2: (4,1) -> CNetworkEX::NextPoint reads _move_request_clzo");
    CHECK(r41.payload == P::Struct && r41.handler == "CNetworkEX::NextPoint" && r41.request == "_move_request_clzo");
    CHECK(!r41.refused() && !r41.trigger());
    const ServerRoute r33 = db.server_route(3, 3);
    check_route(r33, K::Arm, 3, 3,
                "server 2.2.3.2: (3,3) -> CNetworkEX::BaseDownloadRequest -- a trigger: it reads no payload");
    CHECK(r33.payload == P::Unread && r33.trigger() && !r33.refused());
    {
        ServerRoute u = r33;
        u.payload = P::Unknown;
        CHECK_STR(server_text(u, 3, 3),
                  "server 2.2.3.2: (3,3) -> CNetworkEX::BaseDownloadRequest -- no request struct");
        CHECK(!u.trigger());
    }
    const ServerRoute r564 = db.server_route(56, 4);
    check_route(r564, K::Arm, 56, 4,
                "server 2.2.3.2: (56,4) -> PatriarchElectProcessor::Doit(_eVote) -- passes the "
                "payload on (no request struct mapped)");
    CHECK(r564.payload == P::Forwarded && !r564.trigger());
    const ServerRoute r987 = db.server_route(98, 7);
    check_route(r987, K::Any, 98, 7,
                "server 2.2.3.2: (98,7) -> CNationSettingManager::RecvGameGuardData (category 98 takes any sub)");
    CHECK(r987.handler == "CNationSettingManager::RecvGameGuardData");
    const ServerRoute r351 = db.server_route(35, 1);
    check_route(r351, K::Accepted, 35, 1,
                "server 2.2.3.2: NO HANDLER for (35,1) -- category 35 has no arm for sub 1; "
                "its default returns true: accepted, nothing done");
    CHECK(!r351.refused());
    const ServerRoute r3250 = db.server_route(3, 250);
    check_route(r3250, K::NoArm, 3, 250,
                "server 2.2.3.2: NO HANDLER for (3,250) -- category 3 has no arm for sub 250: "
                "returns false -> OddMsg, the server closes the connection");
    CHECK(r3250.refused());
    const ServerRoute r61 = db.server_route(6, 1);
    const char* t61 = "server 2.2.3.2: NO HANDLER for (6,1) -- no case for main 6: returns false -> OddMsg, the server "
                      "closes the connection";
    check_route(r61, K::NoCase, 6, 1, t61);
    CHECK(r61.refused());
    check_route(db.server_route(0, 0), K::NoCase, 0, 0,
                "server 2.2.3.2: NO HANDLER for (0,0) -- no case for main 0: "
                "returns false -> OddMsg, the server closes the connection");
    check_route(db.server_route(100, 1), K::NoCase, 100, 1,
                "server 2.2.3.2: NO HANDLER for (100,1) -- no case for main 100: "
                "returns false -> OddMsg, the server closes the connection");
    const ServerRoute r1011 = db.server_route(101, 1);
    check_route(r1011, K::Internal, 101, 1,
                "server 2.2.3.2: (101,1) -> CNetProcess::_InternalPacketProcess "
                "(main > 100: not ClientLineAnalysis) -- not mapped");
    CHECK(r1011.handler == "CNetProcess::_InternalPacketProcess" && r1011.above == 100 && !r1011.refused());

    CHECK(route_on_host(r61, ""));
    CHECK(route_on_host(r61, "2.2.3.2"));
    CHECK(!route_on_host(r61, "4.15"));
    CHECK(!route_on_host(r61, "EP1P2"));
    CHECK_STR(server_text(r61, 6, 1, "4.15"), std::string(t61) + "  [2.2.3.2 reference -- this client is 4.15]");
    CHECK_STR(server_text(r61, 6, 1, "2.2.3.2"), t61);

    check_cls(db, Dir::C2S, 3, 3, 7, Status::Trigger, "CNetworkEX::BaseDownloadRequest",
              "CNetworkEX::BaseDownloadRequest trigger");
    check_cls(db, Dir::C2S, 56, 4, 5, Status::Unknown, "PatriarchElectProcessor::Doit(_eVote)",
              "PatriarchElectProcessor::Doit(_eVote) unknown(no layout)");
    check_cls(db, Dir::C2S, 99, 2, 16, Status::Unknown, "CNetworkEX::Apex_T", "CNetworkEX::Apex_T unknown(no layout)");
    check_cls(db, Dir::C2S, 98, 7, 4, Status::Unknown, "CNationSettingManager::RecvGameGuardData",
              "CNationSettingManager::RecvGameGuardData unknown(no layout)");
    check_cls(db, Dir::C2S, 3, 250, 2, Status::Unknown, "", "unknown");
    check_cls(db, Dir::C2S, 101, 1, 0, Status::Unknown, "", "unknown");
    check_cls(db, Dir::C2S, 1, 6, 1, Status::Ok, "_moveout_user_request_zone", "_moveout_user_request_zone ok");
    check_cls(db, Dir::S2C, 3, 3, 0, Status::Unknown, "", "unknown");
    {
        const Decoded d = db.classify(Dir::C2S, 3, 3, 0);
        CHECK(d.layout == nullptr && d.candidates.empty());
    }
    size_t triggers = 0;
    for (int m = 0; m < 256; ++m) {
        for (int s = 0; s < 256; ++s) {
            if (db.classify(Dir::C2S, (uint8_t)m, (uint8_t)s, 0).status == Status::Trigger) {
                ++triggers;
            }
        }
    }
    CHECK(triggers == db.server_trigger_count());
    CHECK(triggers == 44);
    std::printf("server route: done\n");
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::printf("usage: test_decode <packet_db.json> <packet_db_mini.json>\nFAILED (1 failure(s))\n");
        return 1;
    }
    PacketDb db, fx;
    std::string e1, e2;
    const bool ok_db = db.load(argv[1], &e1);
    const bool ok_fx = fx.load(argv[2], &e2);
    if (!ok_db) {
        std::printf("FAIL: cannot load %s: %s\n", argv[1], e1.c_str());
        ++g_fail;
    }
    if (!ok_fx) {
        std::printf("FAIL: cannot load %s: %s\n", argv[2], e2.c_str());
        ++g_fail;
    }
    if (ok_db && ok_fx) {
        test_db(db, argv[1]);
        test_classify(fx, db);
        test_client(fx, db);
        test_server(db, argv[1]);
        test_server_route(fx, db);
        test_fields(fx, db);
        test_copy(fx, db);
    }
    if (g_fail) {
        std::printf("FAILED (%d failure(s))\n", g_fail);
    } else {
        std::printf("PASSED (0 failure(s))\n");
    }
    return g_fail ? 1 : 0;
}
