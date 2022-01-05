<template>
  <v-card
    class="mx-auto"
  >
    <h2>Header:</h2><pre>{{header}}</pre>
    <h2>Claims:</h2><pre>{{claims}}</pre>
    <h2>Payload:</h2><pre>{{payload}}</pre>
    <h2>Signature:</h2><pre>{{signature}}</pre>
    <h2>Raw:</h2><pre>{{raw}}</pre>
    <h2>Masked:</h2><pre>{{masked}}</pre>
  </v-card>
</template>

<script>
  export default {
    name: 'JWT',
    
    props: {
      header: Object,
      claims: Object,
      payload: String,
      signature: String,
      raw: String,
      masked: String
    }
  }
</script>
