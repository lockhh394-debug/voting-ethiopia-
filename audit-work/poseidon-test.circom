pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

template Test() {
    signal input a;
    signal output b;

    component h = Poseidon(1);
    h.inputs[0] <== a;
    b <== h.out;
}

component main = Test();