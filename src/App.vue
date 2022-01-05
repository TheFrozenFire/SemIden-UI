<template>
  <v-app>
    <v-app-bar
      app
      color="primary"
      dark
    >
      <div class="d-flex align-center">
        SemIden
      </div>
      <v-spacer />
    </v-app-bar>

    <v-main>
      <SocialLoginButtons />
      
      <v-dialog v-model="show_insert_identity">
        <v-card>
          <v-card-title>Claim Identity</v-card-title>
          <v-btn block>Publicly (bare)</v-btn>
          <v-btn block :loading="proof_is_executing" v-on:click="$root.$emit('jwt-proof')">Privately (ZK proof)</v-btn>
          <v-divider />
          <JWT 
            v-bind="jwt"
          />
        </v-card>
      </v-dialog>
    </v-main>
  </v-app>
</template>

<script>
import {
  client as auth0_config
} from "../auth0.config.js";
import createAuth0Client from '@auth0/auth0-spa-js';

import * as snarkjwt from "snark-jwt-verify";
import * as witness_calculator from "./jwt_proof/witness_calculator.js";
import { groth16 } from "snarkjs/build/main.cjs";
import * as bigInt from "big-integer";

import Web3 from "web3";
import Web3Modal from "web3modal";

import SocialLoginButtons from './components/SocialLoginButtons';
import JWT from './components/JWT';

export default {
  name: 'App',

  components: {
    SocialLoginButtons,
    JWT,
  },
  
  asyncComputed: {
    jwt_wasm: () => fetch(process.env.BASE_URL + 'jwt_proof/jwt_proof.auth0.wasm').then(response => response.arrayBuffer()),
    //jwt_zkey: () => fetch(process.env.BASE_URL + 'jwt_proof/jwt_proof.groth16.zkey').then(response => response.arrayBuffer())
  },
  
  data: () => ({
    show_insert_identity: false,
    proof_is_executing: false,
    jwt: {}
  }),
  
  mounted: async function() {
    const auth0 = await createAuth0Client(auth0_config);
    const app = this;
    
    const web3Modal = new Web3Modal({
      network: "rinkeby",
      cacheProvider: true,
      providerOptions: {
        
      }
    });

    const provider = await web3Modal.connect();

    const web3 = new Web3(provider);
    
    this.$root.$on('social-login', async function(connection) {
      const account = (await web3.eth.getAccounts())[0];
      
      try {
        await auth0.loginWithPopup({connection: connection.name, nonce: account.slice(2, 12)});
      } catch (e) {
        if(e.message.includes('Popup closed')) {
          return;
        } else {
          throw e;
        }
      }
      
      const claims = await auth0.getIdTokenClaims();
      const raw = claims.__raw;
      const [header, payload, signature] = claims.__raw.split('.');
      
      const jwtMask = snarkjwt.circuit.genJwtMask(`${header}.${payload}`, ["sub", "nonce"]);
      const maskedJwt = `${header}.${payload}`.split('').map((c, i) => jwtMask[i] == 1 ? c : "\u2800").join('');
      
      delete claims['__raw'];
      
      app.jwt = {
        header: JSON.parse(Buffer.from(header, 'base64').toString()),
        payload: Buffer.from(payload, 'base64').toString(),
        signature: "0x" + Buffer.from(signature, 'base64').toString('hex'),
        claims: claims,
        raw: raw,
        masked: maskedJwt
      };
      app.show_insert_identity = true;
    });
    
    this.$root.$on('jwt-proof', async function() {
      app.proof_is_executing = true;
      
      const input = app.jwt.raw.split('.').slice(0,2).join('.');
      const signature = app.jwt.raw.split('.')[2];
    
      const inputs = snarkjwt.circuit.genJwtProofInputs(input, 384, ["sub", "nonce"], 8);
      
      const wc = await witness_calculator(app.jwt_wasm);
      const witness = await wc.calculateWTNSBin(inputs);
      
      const {proof, publicSignals} = await groth16.prove(process.env.BASE_URL + 'jwt_proof/jwt_proof.auth0.groth16.zkey', witness);
      
      const hashOut = bigInt(publicSignals[0]).toString(16);
      const maskedCount = Math.ceil((384 * 8) / 248);
      const masked = snarkjwt.utils.bigIntArray2Buffer(publicSignals.slice(1, 1 + maskedCount).map(s => bigInt(s)), 248).toString();
      
      const claims = masked.split(/\x00+/).filter(e => e !== '').map(e => Buffer.from(e, 'base64').toString());
      
      const p256 = (s) => `"0x${bigInt(s).toString(16).padStart(64, '0')}"`;
      
      const calldata = `[${p256(proof.pi_a[0])}, ${p256(proof.pi_a[1])}],` +
        `[[${p256(proof.pi_b[0][1])}, ${p256(proof.pi_b[0][0])}],[${p256(proof.pi_b[1][1])}, ${p256(proof.pi_b[1][0])}]],` +
        `[${p256(proof.pi_c[0])}, ${p256(proof.pi_c[1])}],` +
        `[${publicSignals.map(s => p256(s)).join(',')}]`;
      
      console.log(proof);
      console.log(publicSignals);
      console.log(hashOut);
      console.log(claims);
      console.log(calldata);
      
      app.proof_is_executing = false;
    })
  }
  
};
</script>
