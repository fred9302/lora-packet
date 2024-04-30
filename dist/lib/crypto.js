import{reverseBuffer as w}from"./util.js";import f from"crypto-js";import{Buffer as t}from"buffer";const g=f.enc.Hex.parse("00000000000000000000000000000000");var E=(i=>(i.FNwkSIntKey="01",i.AppSKey="02",i.SNwkSIntKey="03",i.NwkSEncKey="04",i))(E||{}),B=(r=>(r.NwkSKey="01",r.AppSKey="02",r))(B||{}),x=(r=>(r.JSIntKey="06",r.JSEncKey="05",r))(x||{}),K=(r=>(r.WorSIntKey="01",r.WorSEncKey="02",r))(K||{});function m(e,n,r,o){if(!e.PHYPayload||!e.FRMPayload)throw new Error("Payload was not defined");o||(o=t.alloc(2,0));const i=Math.ceil(e.FRMPayload.length/16),c=t.alloc(16*i);for(let h=0;h<i;h++)N(e,h,o).copy(c,h*16);const u=e.getFPort()===0?r:n;if(!u||u.length!==16)throw new Error("Expected a appropriate key with length 16");const d=f.AES.encrypt(f.enc.Hex.parse(c.toString("hex")),f.enc.Hex.parse(u.toString("hex")),{mode:f.mode.ECB,iv:g,padding:f.pad.NoPadding}),p=t.from(d.toString(),"base64"),l=t.alloc(e.FRMPayload.length);for(let h=0;h<e.FRMPayload.length;h++){const s=p.readUInt8(h);l.writeUInt8(s^e.FRMPayload.readUInt8(h),h)}return l}function k(e,n){if(!e?.MACPayloadWithMIC)throw new Error("Expected parsed payload to be defined");if(n.length!==16)throw new Error("Expected a appropriate key with length 16");const r=f.AES.decrypt(e.MACPayloadWithMIC.toString("base64"),f.enc.Hex.parse(n.toString("hex")),{mode:f.mode.ECB,padding:f.pad.NoPadding});return t.from(r.toString(),"hex")}function P(e,n,r){if(r||(r=t.alloc(2)),!e?.FOpts)throw new Error("Expected FOpts to be defined");if(!e?.DevAddr)throw new Error("Expected DevAddr to be defined");if(n.length!==16)throw new Error("Expected a appropriate key with length 16");if(!e.FCnt)throw new Error("Expected FCnt to be defined");const o=t.alloc(1);let i=!1;if(e.getDir()=="up")o.writeUInt8(0,0);else if(e.getDir()=="down")o.writeUInt8(1,0),e.FPort!=null&&e.getFPort()>0&&(i=!0);else throw new Error("Decrypt error: expecting direction to be either 'up' or 'down'");const c=t.concat([t.alloc(1,1),t.alloc(3,0),t.alloc(1,i?2:1),o,w(e.DevAddr),w(e.FCnt),r,t.alloc(1,0),t.alloc(1,1)]),u=f.AES.encrypt(f.enc.Hex.parse(c.toString("hex")),f.enc.Hex.parse(n.toString("hex")),{mode:f.mode.ECB,iv:g,padding:f.pad.NoPadding}),d=t.from(u.toString(),"base64"),p=t.alloc(e.FOpts.length);for(let l=0;l<e.FOpts.length;l++)p[l]=d[l]^e.FOpts[l];return p}function a(e,n,r,o,i){let c=i;c+=w(n).toString("hex"),c+=w(r).toString("hex"),c+=w(o).toString("hex"),c=c.padEnd(32,"0");const u=t.from(c,"hex"),d=f.AES.encrypt(f.enc.Hex.parse(u.toString("hex")),f.enc.Hex.parse(e.toString("hex")),{mode:f.mode.ECB,padding:f.pad.NoPadding});return t.from(d.toString(),"base64")}function F(e,n,r,o){return S(e,n,r,o)}function S(e,n,r,o){if(e.length!==16)throw new Error("Expected a AppKey with length 16");if(n.length!==3)throw new Error("Expected a NetId with length 3");if(r.length!==3)throw new Error("Expected a AppNonce with length 3");if(o.length!==2)throw new Error("Expected a DevNonce with length 2");return{AppSKey:a(e,r,n,o,"02"),NwkSKey:a(e,r,n,o,"01")}}function I(e,n,r,o,i){if(e.length!==16)throw new Error("Expected a AppKey with length 16");if(n.length!==16)throw new Error("Expected a NwkKey with length 16");if(o.length!==3)throw new Error("Expected a AppNonce with length 3");if(i.length!==2)throw new Error("Expected a DevNonce with length 2");return{AppSKey:a(e,o,r,i,"02"),FNwkSIntKey:a(n,o,r,i,"01"),SNwkSIntKey:a(n,o,r,i,"03"),NwkSEncKey:a(n,o,r,i,"04")}}function A(e,n){if(n.length!==8)throw new Error("Expected a DevEui with length 8");if(e.length!==16)throw new Error("Expected a NwkKey with length 16");return{JSIntKey:a(e,n,t.alloc(0),t.alloc(0),"06"),JSEncKey:a(e,n,t.alloc(0),t.alloc(0),"05")}}function b(e){if(e.length!==16)throw new Error("Expected a NwkKey/NwkSEncKey with length 16");return{RootWorSKey:a(e,t.alloc(0),t.alloc(0),t.alloc(0),"01")}}function W(e,n){if(n.length!==4)throw new Error("Expected a DevAddr with length 4");if(e.length!==16)throw new Error("Expected a RootWorSKey with length 16");return{WorSIntKey:a(e,n,t.alloc(0),t.alloc(0),"01"),WorSEncKey:a(e,n,t.alloc(0),t.alloc(0),"02")}}function y(e,n){const r=f.AES.encrypt(f.enc.Hex.parse(e.toString("hex")),f.enc.Hex.parse(n.toString("hex")),{mode:f.mode.ECB,iv:g,padding:f.pad.NoPadding}).ciphertext.toString(f.enc.Hex);return t.from(r,"hex")}function H(e,n){const r=e.PHYPayload||t.alloc(0),o=r.slice(0,1),i=y(r.slice(1),n);return t.concat([o,i])}function N(e,n,r){r||(r=t.alloc(2));let o;if(e.getDir()=="up")o=t.alloc(1,0);else if(e.getDir()=="down")o=t.alloc(1,1);else throw new Error("Decrypt error: expecting direction to be either 'up' or 'down'");if(!e.DevAddr)throw new Error("Decrypt error: DevAddr not defined'");if(!e.FCnt)throw new Error("Decrypt error: FCnt not defined'");return t.concat([t.from("0100000000","hex"),o,w(e.DevAddr),w(e.FCnt),r,t.alloc(1,0),t.alloc(1,n+1)])}export{m as decrypt,P as decryptFOpts,k as decryptJoin,H as decryptJoinAccept,y as encrypt,A as generateJSKeys,F as generateSessionKeys,S as generateSessionKeys10,I as generateSessionKeys11,b as generateWORKey,W as generateWORSessionKeys};