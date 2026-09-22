pragma circom 2.1.6;

include "circomlib/circuits/mux1.circom";

template Test() {
    signal input a;
    signal input b;
    signal input s;
    signal output out;

    component m = Mux1();
    m.c[0] <== a;
    m.c[1] <== b;
    m.s <== s;

    out <== m.out;
}

component main = Test();