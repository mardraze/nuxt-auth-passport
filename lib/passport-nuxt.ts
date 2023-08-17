import { getRouterParam, getQuery } from 'h3'
import passport from 'passport'
import GoogleStrategy from 'passport-google-oidc'
import FacebookStrategy from 'passport-facebook'
import CookieStore from './cookie-store'

export type Provider = {
    clientID: string,
    clientSecret: string,
}

export type Options = {
    providers: Record<string, Provider>,
}

export type PassportNuxtResult = {
    provider: string,
    profile: any,
}

export class PassportNuxt {

    async processRequest(event:any, options:Options){
        return new Promise<PassportNuxtResult>((resolve, reject) => {
            var request: any = event.node.req;
            request.session = {
                regenerate() {

                }
            };
        
            const name = getRouterParam(event, '_')
            const query = getQuery(event)
        
            var arr:Array<string> | undefined = name?.split('/');
            var provider:string = '';
            if(arr){
                provider = arr[0]
            }
            var authenticator = null
            var store = new CookieStore(event, provider);
            if(provider === 'google'){
                authenticator = passport.use(new GoogleStrategy({
                    clientID: options.providers.google.clientID, 
                    clientSecret: options.providers.google.clientSecret, 
                    callbackURL: '/api/auth/'+provider+'/callback',
                    scope: ['profile', 'email'],
                    sessionKey: provider,
                    store: store,
                }, function verify(issuer: any, profile: any, cb: any) {
                    store.clearCookie()
                    resolve({provider, profile})
                    return cb(null, profile)
                }))
            }else if(provider === 'facebook'){
                let graphAPIVersion = 'v17.0';
                authenticator = passport.use(new FacebookStrategy({
                    clientID: options.providers.facebook.clientID,
                    clientSecret: options.providers.facebook.clientSecret,
                    callbackURL: '/api/auth/'+provider+'/callback',
                    sessionKey: provider,
                    store: store,
                    state: true,
                    graphAPIVersion: graphAPIVersion,
                    profileURL: 'https://graph.facebook.com/'+graphAPIVersion+'/me?fields=id,name,email',
                }, function verify(accessToken:any, refreshToken:any, profile:any, cb:any) {
                    store.clearCookie()
                    resolve({provider, profile})
                    if(cb){
                        return cb(null, profile)
                    }
                }))
            }else{
              throw new Error('Invalid provider')
            }
        
            request.query = query;
            authenticator.authenticate(provider, function(){
                reject({provider, arguments});
            })(request, event.node.res, function () {
                reject({provider, arguments});
            });
        });
    }
    
}
