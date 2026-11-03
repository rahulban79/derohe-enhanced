// AUTO-GENERATED from pow.go by cmd/_opcodegen — do not edit.
case 0: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rotl8(s[i],uint(s[i])); uchar ra=rev8(s[p1]), rb=rev8(s[p2]); s[p2]=ra; s[p1]=rb; } break; }
case 1: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rotl8(s[i],1u); s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 2: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rev8(s[i]); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 3: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=rotl8(s[i],3u); s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],1u); } break; }
case 4: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 5: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 6: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rotl8(s[i],3u); s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 7: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 8: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=rotl8(s[i],5u); s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 9: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]^rotl8(s[i],2u); } break; }
case 10: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 11: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=rotl8(s[i],5u); s[i]=s[i]&s[p2]; s[i]=rotl8(s[i],uint(s[i])); } break; }
case 12: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 13: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=rotl8(s[i],5u); } break; }
case 14: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 15: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 16: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rotl8(s[i],1u); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 17: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rotl8(s[i],5u); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 18: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],3u); s[i]=rotl8(s[i],1u); s[i]=rotl8(s[i],5u); } break; }
case 19: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 20: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=s[i]^s[p2]; s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],2u); } break; }
case 21: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=s[i]&s[p2]; } break; }
case 22: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rev8(s[i]); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rotl8(s[i],1u); } break; }
case 23: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=rotl8(s[i],1u); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]&s[p2]; } break; }
case 24: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],5u); } break; }
case 25: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rotl8(s[i],3u); s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 26: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rev8(s[i]); } break; }
case 27: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=s[i]&s[p2]; s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],5u); } break; }
case 28: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rotl8(s[i],5u); } break; }
case 29: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 30: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 31: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 32: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=rev8(s[i]); s[i]=rotl8(s[i],3u); s[i]=s[i]^rotl8(s[i],2u); } break; }
case 33: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^rotl8(s[i],4u); s[i]=rev8(s[i]); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 34: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 35: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); s[i]=rotl8(s[i],1u); s[i]=s[i]^s[p2]; } break; }
case 36: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rotl8(s[i],1u); s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],1u); } break; }
case 37: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 38: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=rotl8(s[i],3u); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rotl8(s[i],uint(s[i])); } break; }
case 39: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]&s[p2]; } break; }
case 40: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^s[p2]; s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^s[p2]; } break; }
case 41: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=rotl8(s[i],3u); s[i]=s[i]^rotl8(s[i],4u); } break; }
case 42: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=rotl8(s[i],3u); s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],uint(s[i])); } break; }
case 43: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 44: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rotl8(s[i],3u); s[i]=rotl8(s[i],uint(s[i])); } break; }
case 45: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=rotl8(s[i],5u); s[i]=s[i]&s[p2]; s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 46: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rotl8(s[i],5u); s[i]=s[i]^rotl8(s[i],4u); } break; }
case 47: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=s[i]&s[p2]; s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 48: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); s[i]=rotl8(s[i],5u); } break; }
case 49: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],4u); } break; }
case 50: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rotl8(s[i],1u); } break; }
case 51: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],5u); } break; }
case 52: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 53: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^rotl8(s[i],4u); } break; }
case 54: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=s[i]^s[p2]; s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 55: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],1u); } break; }
case 56: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); s[i]=rotl8(s[i],1u); } break; }
case 57: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=rotl8(s[i],5u); s[i]=rotl8(s[i],3u); s[i]=rev8(s[i]); } break; }
case 58: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 59: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 60: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rotl8(s[i],3u); } break; }
case 61: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rotl8(s[i],3u); s[i]=rotl8(s[i],5u); } break; }
case 62: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 63: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 64: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 65: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=rotl8(s[i],3u); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 66: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],1u); } break; }
case 67: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],5u); } break; }
case 68: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^s[p2]; } break; }
case 69: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rev8(s[i]); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 70: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]^rotl8(s[i],4u); } break; }
case 71: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 72: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 73: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rev8(s[i]); s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 74: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rotl8(s[i],3u); s[i]=rev8(s[i]); s[i]=s[i]&s[p2]; } break; }
case 75: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]&s[p2]; s[i]=s[i]^rotl8(s[i],4u); } break; }
case 76: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 77: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 78: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=rev8(s[i]); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 79: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 80: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=s[i]&s[p2]; } break; }
case 81: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 82: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 83: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rev8(s[i]); s[i]=rotl8(s[i],3u); s[i]=rev8(s[i]); } break; }
case 84: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=rotl8(s[i],1u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 85: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 86: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 87: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rotl8(s[i],3u); s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 88: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],1u); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 89: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]^rotl8(s[i],2u); } break; }
case 90: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=rotl8(s[i],5u); s[i]=rotl8(s[i],1u); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 91: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]&s[p2]; s[i]=s[i]^rotl8(s[i],4u); s[i]=rev8(s[i]); } break; }
case 92: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]&s[p2]; } break; }
case 93: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 94: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 95: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=uchar(0xffu^uint(s[i])); s[i]=rotl8(s[i],5u); s[i]=rotl8(s[i],5u); } break; }
case 96: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rotl8(s[i],1u); } break; }
case 97: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 98: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]^rotl8(s[i],4u); } break; }
case 99: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=rev8(s[i]); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 100: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rev8(s[i]); s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 101: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 102: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rotl8(s[i],3u); } break; }
case 103: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=rev8(s[i]); s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],uint(s[i])); } break; }
case 104: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 105: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rotl8(s[i],3u); s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^rotl8(s[i],2u); } break; }
case 106: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],1u); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 107: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],5u); s[i]=rotl8(s[i],1u); } break; }
case 108: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]&s[p2]; s[i]=s[i]^rotl8(s[i],2u); } break; }
case 109: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^s[p2]; s[i]=s[i]^rotl8(s[i],2u); } break; }
case 110: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 111: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rev8(s[i]); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 112: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=uchar(0xffu^uint(s[i])); s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 113: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=rotl8(s[i],1u); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 114: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=rev8(s[i]); s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 115: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=rotl8(s[i],5u); s[i]=s[i]&s[p2]; s[i]=rotl8(s[i],3u); } break; }
case 116: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=s[i]^s[p2]; s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 117: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]&s[p2]; } break; }
case 118: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rotl8(s[i],5u); } break; }
case 119: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]^s[p2]; } break; }
case 120: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]^s[p2]; s[i]=rev8(s[i]); } break; }
case 121: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 122: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],uint(s[i])); s[i]=rotl8(s[i],5u); s[i]=s[i]^rotl8(s[i],2u); } break; }
case 123: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=uchar(0xffu^uint(s[i])); s[i]=rotl8(s[i],3u); s[i]=rotl8(s[i],3u); } break; }
case 124: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^s[p2]; s[i]=uchar(0xffu^uint(s[i])); } break; }
case 125: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 126: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=rotl8(s[i],1u); s[i]=rotl8(s[i],5u); s[i]=rev8(s[i]); } break; }
case 127: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]&s[p2]; s[i]=s[i]^s[p2]; } break; }
case 128: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],5u); } break; }
case 129: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 130: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=rotl8(s[i],uint(s[i])); s[i]=rotl8(s[i],1u); s[i]=s[i]^rotl8(s[i],4u); } break; }
case 131: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=rotl8(s[i],1u); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 132: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=rev8(s[i]); s[i]=rotl8(s[i],5u); s[i]=s[i]^rotl8(s[i],2u); } break; }
case 133: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],5u); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 134: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],1u); s[i]=s[i]&s[p2]; } break; }
case 135: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rev8(s[i]); } break; }
case 136: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],5u); } break; }
case 137: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=rev8(s[i]); s[i]=rotl8(s[i],uint(s[i])); } break; }
case 138: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 139: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=rotl8(s[i],3u); s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],3u); } break; }
case 140: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],5u); } break; }
case 141: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 142: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=rotl8(s[i],5u); s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],2u); } break; }
case 143: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 144: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(0xffu^uint(s[i])); s[i]=rotl8(s[i],uint(s[i])); } break; }
case 145: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^rotl8(s[i],4u); } break; }
case 146: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]&s[p2]; s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 147: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 148: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 149: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=rev8(s[i]); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 150: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]&s[p2]; } break; }
case 151: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 152: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]^rotl8(s[i],2u); } break; }
case 153: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=rotl8(s[i],3u); s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 154: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]^s[p2]; s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 155: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=s[i]^s[p2]; s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^s[p2]; } break; }
case 156: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=rotl8(s[i],3u); s[i]=rotl8(s[i],1u); } break; }
case 157: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rotl8(s[i],uint(s[i])); s[i]=rotl8(s[i],1u); } break; }
case 158: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rotl8(s[i],1u); } break; }
case 159: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^s[p2]; } break; }
case 160: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=rev8(s[i]); s[i]=rotl8(s[i],1u); s[i]=rotl8(s[i],3u); } break; }
case 161: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],5u); s[i]=rotl8(s[i],uint(s[i])); } break; }
case 162: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 163: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],1u); } break; }
case 164: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 165: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 166: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 167: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 168: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]&s[p2]; s[i]=rotl8(s[i],uint(s[i])); s[i]=rotl8(s[i],1u); } break; }
case 169: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]&s[p2]; } break; }
case 170: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=rev8(s[i]); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 171: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rev8(s[i]); } break; }
case 172: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rotl8(s[i],1u); } break; }
case 173: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 174: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 175: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rotl8(s[i],5u); } break; }
case 176: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],5u); } break; }
case 177: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]&s[p2]; } break; }
case 178: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); s[i]=rotl8(s[i],1u); } break; }
case 179: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=rev8(s[i]); } break; }
case 180: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 181: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],5u); } break; }
case 182: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],1u); s[i]=rotl8(s[i],5u); s[i]=s[i]^rotl8(s[i],4u); } break; }
case 183: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 184: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rotl8(s[i],5u); s[i]=s[i]^s[p2]; } break; }
case 185: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 186: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 187: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rotl8(s[i],3u); } break; }
case 188: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^rotl8(s[i],4u); } break; }
case 189: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 190: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]&s[p2]; s[i]=s[i]^rotl8(s[i],2u); } break; }
case 191: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rotl8(s[i],3u); s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 192: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 193: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rotl8(s[i],uint(s[i])); s[i]=rotl8(s[i],1u); } break; }
case 194: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]&s[p2]; } break; }
case 195: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^s[p2]; s[i]=s[i]^rotl8(s[i],4u); } break; }
case 196: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=rev8(s[i]); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rotl8(s[i],1u); } break; }
case 197: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 198: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=rev8(s[i]); s[i]=rotl8(s[i],1u); } break; }
case 199: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]^s[p2]; } break; }
case 200: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rev8(s[i]); s[i]=rev8(s[i]); } break; }
case 201: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 202: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=uchar(0xffu^uint(s[i])); s[i]=rotl8(s[i],uint(s[i])); s[i]=rotl8(s[i],5u); } break; }
case 203: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=s[i]&s[p2]; s[i]=rotl8(s[i],1u); s[i]=rotl8(s[i],uint(s[i])); } break; }
case 204: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^s[p2]; } break; }
case 205: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 206: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=rev8(s[i]); s[i]=rev8(s[i]); s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 207: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=rotl8(s[i],3u); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 208: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=rotl8(s[i],3u); } break; }
case 209: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=rev8(s[i]); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 210: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],uint(s[i])); s[i]=rotl8(s[i],5u); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 211: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=rotl8(s[i],uint(s[i])); } break; }
case 212: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^s[p2]; s[i]=s[i]^s[p2]; } break; }
case 213: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 214: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 215: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 216: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=s[i]&s[p2]; } break; }
case 217: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rotl8(s[i],1u); s[i]=s[i]^rotl8(s[i],4u); } break; }
case 218: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 219: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],3u); s[i]=s[i]&s[p2]; s[i]=rev8(s[i]); } break; }
case 220: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=rev8(s[i]); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 221: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=s[i]^s[p2]; s[i]=uchar(0xffu^uint(s[i])); s[i]=rev8(s[i]); } break; }
case 222: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])*uint(s[i])); } break; }
case 223: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],uint(s[i])); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 224: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],1u); s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 225: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=rev8(s[i]); s[i]=rotl8(s[i],3u); } break; }
case 226: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]^s[p2]; } break; }
case 227: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=s[i]&s[p2]; } break; }
case 228: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 229: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 230: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]&s[p2]; s[i]=rotl8(s[i],uint(s[i])); s[i]=rotl8(s[i],uint(s[i])); } break; }
case 231: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]^s[p2]; s[i]=rev8(s[i]); } break; }
case 232: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],5u); } break; }
case 233: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],1u); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rotl8(s[i],3u); s[i]=s[i]^uchar(popcount(uint(s[i]))); } break; }
case 234: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=s[i]^s[p2]; } break; }
case 235: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=rotl8(s[i],3u); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 236: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^s[p2]; s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 237: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],3u); } break; }
case 238: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rotl8(s[i],3u); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); } break; }
case 239: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=rotl8(s[i],1u); s[i]=uchar(uint(s[i])*uint(s[i])); s[i]=s[i]&s[p2]; } break; }
case 240: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=s[i]&s[p2]; s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 241: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],1u); } break; }
case 242: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=s[i]^s[p2]; } break; }
case 243: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rotl8(s[i],1u); } break; }
case 244: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=s[i]^rotl8(s[i],2u); s[i]=rev8(s[i]); s[i]=rotl8(s[i],5u); } break; }
case 245: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=rotl8(s[i],5u); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); } break; }
case 246: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=rotl8(s[i],1u); s[i]=uchar(uint(s[i])>>(uint(s[i])&3u)); s[i]=uchar(uint(s[i])+uint(s[i])); } break; }
case 247: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],5u); s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],5u); s[i]=uchar(0xffu^uint(s[i])); } break; }
case 248: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(0xffu^uint(s[i])); s[i]=uchar(uint(s[i])-(uint(s[i])^97u)); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rotl8(s[i],5u); } break; }
case 249: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^rotl8(s[i],4u); s[i]=rotl8(s[i],uint(s[i])); } break; }
case 250: {
  for(uint i=p1;i<p2;i++){ s[i]=s[i]&s[p2]; s[i]=rotl8(s[i],uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=s[i]^rotl8(s[i],4u); } break; }
case 251: {
  for(uint i=p1;i<p2;i++){ s[i]=uchar(uint(s[i])+uint(s[i])); s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],2u); } break; }
case 252: {
  for(uint i=p1;i<p2;i++){ s[i]=rev8(s[i]); s[i]=s[i]^rotl8(s[i],4u); s[i]=s[i]^rotl8(s[i],2u); s[i]=uchar(uint(s[i])<<(uint(s[i])&3u)); } break; }
case 253: {
  for(uint i=p1;i<p2;i++){ s[i]=rotl8(s[i],3u); s[i]=s[i]^rotl8(s[i],2u); s[i]=s[i]^s[p2]; s[i]=rotl8(s[i],3u); prev_lhash=lhash+prev_lhash; lhash=xxh64(s,p2); } break; }
case 254: case 255: {
  rc4_ksa(&r, s);
  for(uint i=p1;i<p2;i++){ s[i]=s[i]^uchar(popcount(uint(s[i]))); s[i]=rotl8(s[i],3u); s[i]=s[i]^rotl8(s[i],2u); s[i]=rotl8(s[i],3u); } break; }
