pragma circom 2.1.6;

template Test() {
    signal input a;
    signal output b;
    b <== a;
}

component main = Test();