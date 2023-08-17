import { getRouterParam, getQuery, getCookie, setCookie, deleteCookie } from 'h3'
import passport from 'passport'
import GoogleStrategy from 'passport-google-oidc'
import FacebookStrategy from 'passport-facebook'

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

export class CookieStore {
    event: any;
    provider: any;
    constructor(event: any, provider: string) {
        this.event = event;
        this.provider = provider;
    }
    store(req: any, ctx: any, appState: any, meta: any, cb: any) {
        function makeid(length: number) {
            let result = '';
            const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            const charactersLength = characters.length;
            let counter = 0;
            while (counter < length) {
                result += characters.charAt(Math.floor(Math.random() * charactersLength));
                counter += 1;
            }
            return result;
        }
        var key = this.provider;
        var handle = makeid(32);

        var state: any = { handle: handle };
        if (ctx) {
            if (ctx.maxAge) { state.maxAge = ctx.maxAge; }
            if (ctx.nonce) { state.nonce = ctx.nonce; }
            if (ctx.issued) { state.issued = ctx.issued; }
        }
        if (appState) { state.state = appState; }

        if (!req.session[key]) { req.session[key] = {}; }
        req.session[key].state = state;

        setCookie(this.event, 'state_' + this.provider, JSON.stringify(state))

        cb(null, handle);
    }

    verify(req: any, handle: string, cb: any) {
        try {
            var ctx: any = JSON.parse(getCookie(this.event, 'state_' + this.provider) || '')
        } catch (e) {
            var ctx: any = {}
        }
        if (typeof ctx.issued === 'string') {
            ctx.issued = new Date(ctx.issued);
        }
        return cb(null, ctx, ctx.handle);
    }

    clearCookie() {
        deleteCookie(this.event, 'state_' + this.provider)
    }
};

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
