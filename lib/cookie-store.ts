import { getCookie, setCookie, deleteCookie } from 'h3'

export default class CookieStore {
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