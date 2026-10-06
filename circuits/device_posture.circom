pragma circom 2.1.6;

// ==========================================================================
//  Mạch DevicePosture – quan hệ R(x, w) của hệ thống ZKP-ZTNA 
//  Thiết bị (Prover) chứng minh:
//    "Tôi có một credential do Issuer ký, thuộc tính trong đó thỏa chính sách
//     của nguồn tài nguyên, credential gắn với khóa bí mật của tôi, còn hạn,
//     và bằng chứng này dành riêng cho nonce của phiên hiện tại"
//  mà không tiết lộ fw, sec, dtype, exp, sk_dev, chữ ký.
// ==========================================================================

include "circomlib/circuits/poseidon.circom"; // cung cap ham bam
include "circomlib/circuits/comparators.circom"; // cac mach gia so dai so
include "circomlib/circuits/bitify.circom";      // chuyen doi bit, chong tran so, gioi han bit
include "circomlib/circuits/eddsaposeidon.circom";  // xác minh chu ky so EdDSA

template DevicePosture(K) {
    // ---------- Private input (witness w) – chỉ thiết bị biết ----------
    signal input sk_dev;   // khóa bí mật của thiết bị, chống sao chép credential sang máy khác
    signal input fw;       // phiên bản firmware (vd 502 = 5.0.2)
    signal input sec;      // mức an toàn (0–255)
    signal input dtype;    // loại thiết bị (1 nhiệt, 2 ẩm, 3 camera, 4 gateway)
    signal input exp;      // hạn credential (Unix time, giây)
    signal input R8x;      // chữ ký σ = (R8, S) của Issuer trên C, 
                            //R8 là một điểm trên đường cong BabyJubjub có tọa độ (R8x, R8y), và S là một số nguyên vô hướng.
    signal input R8y;
    signal input S;

    // ---------- Public input (x) – PDP tự điền, không lấy từ thiết bị ----------
    signal input Ax;               // khóa công khai của Issuer (tin cậy)
    signal input Ay;
    signal input minFw;            // chính sách để truy cập vào tài nguyên 
    signal input minSec;
    signal input allowedTypes[K];
    signal input now;              // thời điểm PDP cấp cùng nonce
    signal input nonce;            // số dùng một lần của phiên

    signal output sessionTag;      // thẻ phiên, công khai

    //Kiểm tra miền giá trị: ép fw, sec, exp nằm trong số bit cho phép,
    // để phép so sánh trên trường F_p không bị tràn.
    component rFw  = Num2Bits(16); rFw.in  <== fw;
    component rSec = Num2Bits(8);  rSec.in <== sec;
    component rExp = Num2Bits(32); rExp.in <== exp;

    // [SR4] Ràng buộc chủ sở hữu: pk_dev = Poseidon(sk_dev).
    // pk_dev được đưa vào commitment C, nên ai không có sk_dev thì không dùng
    // được credential (kể cả khi sao chép được file credential).
    component pk = Poseidon(1);
    pk.inputs[0] <== sk_dev;

    // [SR3] Xác thực nguồn gốc: C = Poseidon(pk_dev, fw, sec, dtype, exp)
    // và σ phải là chữ ký EdDSA hợp lệ của Issuer (Ax, Ay) trên C.
    // Sửa bất kỳ thuộc tính nào -> C đổi -> chữ ký không còn khớp.
    component cred = Poseidon(5);
    cred.inputs[0] <== pk.out;
    cred.inputs[1] <== fw;
    cred.inputs[2] <== sec;
    cred.inputs[3] <== dtype;
    cred.inputs[4] <== exp;

    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax  <== Ax;   sig.Ay  <== Ay;
    sig.R8x <== R8x;  sig.R8y <== R8y;  sig.S <== S;
    sig.M   <== cred.out;

    // [SR1, SR2] Điều kiện chính sách: fw >= minFw, sec >= minSec
    component geFw = GreaterEqThan(16);
    geFw.in[0] <== fw;  geFw.in[1] <== minFw;
    geFw.out === 1;

    component geSec = GreaterEqThan(8);
    geSec.in[0] <== sec; geSec.in[1] <== minSec;
    geSec.out === 1;

    // [SR8] Còn hạn: exp >= now
    component notExpired = GreaterEqThan(32);
    notExpired.in[0] <== exp; notExpired.in[1] <== now;
    notExpired.out === 1;

    // [SR1, SR2] dtype thuộc tập cho phép: tích (dtype - a_i) phải bằng 0,
    // tức dtype trùng ít nhất một phần tử – mà không lộ là phần tử nào.
    signal prod[K];
    prod[0] <== dtype - allowedTypes[0];
    for (var i = 1; i < K; i++) {
        prod[i] <== prod[i-1] * (dtype - allowedTypes[i]);
    }
    prod[K-1] === 0;

    // [SR5, SR7] Ràng buộc phiên: sessionTag = Poseidon(sk_dev, nonce).
    // Nonce là public input nên proof chỉ đúng với nonce của phiên này;
    // mỗi nonce cho một sessionTag khác nhau nên không liên kết được các phiên.
    component tag = Poseidon(2);
    tag.inputs[0] <== sk_dev;
    tag.inputs[1] <== nonce;
    sessionTag <== tag.out;
}

// [SR6] Toàn vẹn chính sách: các tham số chính sách là public input,
// PDP tự điền lại khi kiểm tra, nên thiết bị không thể tự hạ ngưỡng.
component main {public [Ax, Ay, minFw, minSec, allowedTypes, now, nonce]}
    = DevicePosture(3);