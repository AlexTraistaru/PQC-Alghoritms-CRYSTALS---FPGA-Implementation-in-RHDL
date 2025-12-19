// Kyber512 params (nivel 1): k=2, eta1=3, eta2=2, du=10, dv=4
use rhdl::prelude::*;

pub const KYBER_N: usize = 256;
pub const KYBER_Q: i32 = 3329;

pub const QINV: i32 = -3327;
pub const BARRETT_V: i32 = 20159;
pub const N: usize = 256;
pub const Q: i16 = 3329;

pub const K: usize = 2;
pub const ETA1: usize = 3;
pub const ETA2: usize = 2;
pub const DU: usize = 10;
pub const DV: usize = 4;

pub const SYMBYTES: usize = 32;

pub const POLYBYTES: usize = 384; // 256*12/8
pub const POLYCOMPRESSEDBYTES_DU10: usize = 320; // 256*10/8
pub const POLYCOMPRESSEDBYTES_DV4: usize = 128;  // 256*4/8

pub const POLYVECBYTES: usize = K * POLYBYTES;                 // 768
pub const POLYVECCOMPRESSEDBYTES: usize = K * POLYCOMPRESSEDBYTES_DU10; // 640

pub const PUBLICKEYBYTES: usize = POLYVECBYTES + SYMBYTES; // 800
pub const INDCPA_SECRETKEYBYTES: usize = POLYVECBYTES;     // 768
pub const CIPHERTEXTBYTES: usize = POLYVECCOMPRESSEDBYTES + POLYCOMPRESSEDBYTES_DV4; // 768

pub const SECRETKEYBYTES: usize = INDCPA_SECRETKEYBYTES + PUBLICKEYBYTES + 2 * SYMBYTES; // 1632

// f = 1441 in Kyber reference
pub const INVNTT_F: i16 = 1441;

// Kyber Round3 reference zetas[128] (pq-crystals/kyber ref)

pub const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628,
];
