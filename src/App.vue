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

    </v-app-bar>

    <v-main>
      <SocialLoginButtons />
      
      <v-dialog v-model="show_insert_identity">
        <JWT v-bind:jwt="jwt" />
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
///import * as witness_calculator from "./jwt_proof/witness_calculator.js";

import SocialLoginButtons from './components/SocialLoginButtons';
import JWT from './components/JWT';

export default {
  name: 'App',

  components: {
    SocialLoginButtons,
    JWT,
  },
  
  asyncComputed: {
    jwt_wasm: () => fetch(process.env.BASE_URL + 'jwt_proof.wasm').then(response => response.arrayBuffer()),
  },
  
  data: () => ({
    show_insert_identity: false,
    jwt: {},
  }),
  
  mounted: async function() {
    const auth0 = await createAuth0Client(auth0_config);
    const app = this;
    
    this.$root.$on('social-login', async function(connection) {
      await auth0.loginWithPopup({connection: connection.name});
      
      const claims = await auth0.getIdTokenClaims();
      const [header, payload, signature] = claims.__raw.split('.');
      
      app.jwt = {
        header: Buffer.from(header, 'base64').toString(),
        payload: Buffer.from(payload, 'base64').toString(),
        signature: "0x" + Buffer.from(signature, 'base64').toString('hex'),
        claims: claims,
      };
      app.show_insert_identity = true;
      
      console.log(app.jwt.payload);
      const inputs = snarkjwt.genClaimProofInputs(app.jwt.payload, 300, "sub");
      
      console.log(inputs);
      
      /*const wc = await witness_calculator(app.jwt_wasm);
      
      const witness = await wc.calculateWitness({
        "
      });
      
      console.log(witness);*/
    });
  }
};
</script>
