// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
  "encoding/json"
  "net"
  "net/url"
  "os"
  "path/filepath"
  "strings"
  "testing"
)

func TestOwnerQwdttAnonymousExactWorkerBudgets(t *testing.T) {
 for _,tc := range []struct{
   label string
   workers int
   hashes string
   minKiB int64
   wantGroups []int
   wantHashOrder []string
 }{
   {"single16",16,"oneHash",147456,[]int{9,7},[]string{"oneHash","oneHash"}},
   {"single18",18,"oneHash",155648,[]int{9,9},[]string{"oneHash","oneHash"}},
   {"dual18",18,"oneHash,twoHash",155648,[]int{9,9},[]string{"oneHash","twoHash"}},
 }{
   t.Run(tc.label,func(t *testing.T){
     opts:=qAnonOpts()
     opts.MaxWorkers=tc.workers
     c,name,err:=qParse([]byte(qURI(fmtInt(tc.workers),tc.hashes)),opts,tc.minKiB)
     if err!=nil || name!="Synthetic" || c.Workers!=tc.workers ||
       c.QWDTTRequestedWorkers!=tc.workers || c.QWDTTEffectiveWorkers!=tc.workers ||
       c.Auth!="anonymous" || labValidate(c)!=nil {
       t.Fatalf("exact worker import denied: %v",err)
     }
     if got:=labAnonymousEffectiveWorkers(c.Workers,c.QWDTTRequestedWorkers);got!=tc.workers {
       t.Fatalf("workers truncated from %d to %d",tc.workers,got)
     }
     ng:=(c.Workers+workersPerGroup-1)/workersPerGroup
     if ng!=len(tc.wantGroups){t.Fatal("unexpected runtime group count")}
     for group:=0;group<ng;group++ {
       start:=group*workersPerGroup
       end:=start+workersPerGroup
       if end>c.Workers {end=c.Workers}
       if end-start!=tc.wantGroups[group] {t.Fatal("wrong worker IDs/group")}
       hashes:=ParseHashes(c.VK)
       usedHash:=hashes[group%len(hashes)]
       if usedHash!=tc.wantHashOrder[group] {t.Fatal("incorrect anonymous hash selected for group")}
     }
     if _,_,err:=qParse([]byte(qURI(fmtInt(tc.workers),tc.hashes)),opts,tc.minKiB-1);
         err==nil || !strings.Contains(err.Error(),"MEMORY_INSUFFICIENT") {
       t.Fatal("imported without sufficient available RAM")
     }
     bad:=opts
     bad.MaxWorkers=tc.workers-1
     if _,_,err:=qParse([]byte(qURI(fmtInt(tc.workers),tc.hashes)),bad,200000);err==nil{
       t.Fatal("without explicit max-workers consent")
     }
     if tc.workers==16 {
       if _,_,err:=qParse([]byte(qURI(fmtInt(tc.workers),tc.hashes+",another")),opts,200000);err==nil {
         t.Fatal("16 with two hashes unexpectedly allowed")
       }
     }else if tc.workers==18 {
       if _,_,err:=qParse([]byte(qURI(fmtInt(tc.workers),"oneHash,twoHash,thirdHash")),opts,200000);err==nil{
         t.Fatal("18 with three hashes unexpectedly allowed")
       }
     }
     broken:=c
     broken.QWDTTRequestedWorkers=9
     if labValidate(broken)==nil {t.Fatal("untrusted worker-count metadata accepted")}
     broken=c
     broken.QWDTTEffectiveWorkers=9
     if labValidate(broken)==nil {t.Fatal("false effective worker count accepted")}
     broken=c
     broken.Workers=12
     if labValidate(broken)==nil {t.Fatal("workers manipulated after import")}
   })
 }
 for _,tc:=range []struct{request int; annotation int; expected int}{
   {12,0,9}, {12,9,9}, {16,0,9}, {16,16,16},
   {18,0,18}, {18,18,18}, {9,0,9}, {3,0,9},
 } {
   if got:=labAnonymousEffectiveWorkers(tc.request,tc.annotation);got!=tc.expected {
     t.Fatalf("requested %d annotated %d: got %d expected %d",tc.request,tc.annotation,got,tc.expected)
   }
 }
}

func TestOwnerQwdtt16And18PrivateOfflineImport(t *testing.T) {
 for _,tc:=range []struct{workers int;hashes string}{
   {16,"oneHash"}, {18,"oneHash"}, {18,"oneHash,twoHash"},
 }{
   t.Run(fmtInt(tc.workers),func(t *testing.T){
     d:=t.TempDir()
     if err:=os.Chmod(d,0700);err!=nil{t.Fatal(err)}
     sock,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
     if err!=nil{t.Fatal(err)}
     port:=sock.LocalAddr().(*net.UDPAddr).Port
     sock.Close()
     u,_:=url.Parse(qURI(fmtInt(tc.workers),tc.hashes))
     params:=u.Query()
     params.Set("port",fmtInt(port))
     u.RawQuery=params.Encode()
     in:=filepath.Join(d,"profile.uri")
     out:=filepath.Join(d,"out.json")
     if err:=os.WriteFile(in,[]byte(u.String()+"\n"),0600);err!=nil{t.Fatal(err)}
     o:=qAnonOpts()
     o.Input,o.Output=in,out
     o.MaxWorkers=tc.workers
     if err:=qImport(o);err!=nil{t.Fatalf("qWDTT private import denied: %v",err)}
     st,err:=os.Stat(out)
     if err!=nil || st.Mode().Perm()!=0600 {t.Fatal("unsafe output permissions")}
     b,err:=os.ReadFile(out)
     if err!=nil{t.Fatal(err)}
     var decoded labConfig
     if json.Unmarshal(b,&decoded)!=nil || decoded.Workers!=tc.workers ||
       decoded.QWDTTRequestedWorkers!=tc.workers ||
       decoded.QWDTTEffectiveWorkers!=tc.workers ||
       labValidate(decoded)!=nil {
       t.Fatal("private worker metadata not validated")
     }
     if err:=qImport(o);err==nil{t.Fatal("unsafe overwrite")}
   })
 }
}
