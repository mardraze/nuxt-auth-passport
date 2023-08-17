import { defineEventHandler } from 'h3'

import {PassportNuxt, PassportNuxtResult} from '../../../lib/passport-nuxt'

export default defineEventHandler((event) => {
  return new Promise<any>(() => {
    const passportForNuxt = new PassportNuxt();

    passportForNuxt.processRequest(event, {
      providers: {
        google: {
          clientID: process.env['GOOGLE_ID'] || '',
          clientSecret: process.env['GOOGLE_SECRET'] || '',
        },
        facebook: {
          clientID: process.env['FACEBOOK_ID'] || '',
          clientSecret: process.env['FACEBOOK_SECRET'] || '',
        },
      }
    }).then((result:PassportNuxtResult) => {
      console.log('result', result.provider, result.profile); 

      //You have to implement your own logic related with the result
      //For example, you can save the result.profile to your database and set a cookie to your browser

      let email = ''
      if(result.provider === 'google' && result.profile.emails && result.profile.emails.length > 0){
        email = result.profile.emails[0].value
      } else if(result.provider === 'facebook' && result.profile.emails && result.profile.emails.length > 0){
        email = result.profile.emails[0].value
      }
      event.node.res.writeHead(302, { Location: '/?email=' + email }); //redirect to your profile page
      event.node.res.end();
        
    }).catch(() => {
      event.node.res.writeHead(302, { Location: '/' }); //redirect to your login page
      event.node.res.end();
    })
  })
})
