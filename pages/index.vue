<script lang="ts" setup>
import { useRoute } from 'vue-router'
import { ref } from 'vue'

const route = useRoute()
const email = ref(route.query.email ? route.query.email : '')

</script>

<template>
<div>
    <a href="/api/auth/facebook">Sign in with Facebook</a>
    <br/>
    <a href="/api/auth/google">Sign in with Google</a>

    <div v-if="email">Your email is {{ email }}</div>
</div>
</template>
