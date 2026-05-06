# CrafyCAPTCHA Node.js SDK

Implementation of CrafyCAPTCHA for backend in Node.js

## Installation

```bash
npm install crafy-captcha
```

## Basic use

```javascript
const CrafyCAPTCHA = require('crafy-captcha');

async function test() {
    const captcha = new CrafyCAPTCHA('pk_your_public', 'sk_your_secret');
    
    // Iframe options
    const options = await captcha.createFlow({ theme: 'dark' });
    console.log(options);
}
test();
```