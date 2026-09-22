pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mux1.circom";

template Merkle3() {
    signal input leaf;
    signal input root;
    signal input pathElements[3];
    signal input pathIndices[3];

    signal node[4];
    signal left[3];
    signal right[3];

    component pathHasher[3];
    component leftMux[3];
    component rightMux[3];

    node[0] <== leaf;

    for (var i = 0; i < 3; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        leftMux[i] = Mux1();
        leftMux[i].c[0] <== node[i];
        leftMux[i].c[1] <== pathElements[i];
        leftMux[i].s <== pathIndices[i];
        left[i] <== leftMux[i].out;

        rightMux[i] = Mux1();
        rightMux[i].c[0] <== pathElements[i];
        rightMux[i].c[1] <== node[i];
        rightMux[i].s <== pathIndices[i];
        right[i] <== rightMux[i].out;

        pathHasher[i] = Poseidon(2);
        pathHasher[i].inputs[0] <== left[i];
        pathHasher[i].inputs[1] <== right[i];
        node[i + 1] <== pathHasher[i].out;
    }

    root === node[3];
}

component main = Merkle3();