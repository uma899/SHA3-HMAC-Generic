`timescale 1ns/1ps
// Self-checking testbench for hmac_sha3. Vectors come from a text file made by
// gen_hmac_vectors.py (reference = Python hmac). Run:
//   python3 gen_hmac_vectors.py            -> vec_pd.txt
//   iverilog -g2005 -o sim tb_hmac_sha3.v hmac_sha3.v sha3_core.v keccak_round.v round_constant.v
//   vvp sim [+VEC=vec_pd.txt]
// Random valid gaps on key/msg and random out_ready backpressure are applied.
module tb_hmac_sha3_pd;   // processor model: sends key twice, pads message itself
 reg [255:0] vecfile;
 reg clk=0, rst_n=0; always #5 clk=~clk;
 integer wd=0, tcur=0;
 reg start=0; reg [1:0] mode=0;
 wire ready; reg key_valid=0; wire key_ready; reg [31:0] key_data=0;
 reg msg_valid=0; wire msg_ready; reg [31:0] msg_data=0; reg msg_last=0;
 wire out_valid; reg out_ready=0; wire [31:0] out_data; wire out_last;
 reg key_last=0;
 hmac_sha3 dut(clk,rst_n,start,mode,ready,key_valid,key_ready,key_data,key_last,msg_valid,msg_ready,msg_data,msg_last,out_valid,out_ready,out_data,out_last);
 reg [7:0] kb[0:1023]; reg [7:0] mb[0:2047]; integer rb,pl,pass; reg [7:0] eb[0:63]; reg [7:0] gb[0:63];
 integer fd,n,t,i,m,kl,ml,dl,r,w,nw,errs=0,got,rem;
 reg [31:0] d;
 initial begin
  if(!$value$plusargs("VEC=%s",vecfile)) vecfile="vec_pd.txt"; fd=$fopen(vecfile,"r"); if(fd==0) begin $display("FAIL: cannot open vector file"); $finish; end r=$fscanf(fd,"%d",n);
  repeat(3) @(posedge clk); rst_n=1; @(negedge clk);
  for(t=0;t<n;t=t+1) begin
    r=$fscanf(fd,"%d %d %d %d",m,kl,ml,dl);
    for(i=0;i<kl;i=i+1) begin r=$fscanf(fd,"%h",d); kb[i]=d[7:0]; end
    for(i=0;i<ml;i=i+1) begin r=$fscanf(fd,"%h",d); mb[i]=d[7:0]; end
    for(i=0;i<dl;i=i+1) begin r=$fscanf(fd,"%h",d); eb[i]=d[7:0]; end
    tcur=t; wd=0;
    $display("test %0d/%0d  mode=%0d  keylen=%0d  msglen=%0d",t+1,n,m,kl,ml);
    if(kl > ((m==0)?144:(m==1)?136:(m==2)?104:72)) begin $display("  SKIPPED: key longer than block size is not supported (hash it first in software)"); end else begin
    while(!ready) @(negedge clk);
    mode=m; start=1; @(negedge clk); start=0;
    rb = (m==0)?144:(m==1)?136:(m==2)?104:72;
    pl = ((ml/rb)+1)*rb;
    for(i=ml;i<pl;i=i+1) mb[i]=8'h00;
    mb[ml] = mb[ml] | 8'h06;  mb[pl-1] = mb[pl-1] | 8'h80;
    for(pass=0;pass<2;pass=pass+1) begin
      // key stream (twice: before and after the message); empty key = one zero word
      nw=(kl+3)/4; if(nw==0) nw=1;
      for(w=0;w<nw;w=w+1) begin
        while($random & 1) @(negedge clk);
        d=0; for(i=0;i<4;i=i+1) if(w*4+i<kl) d[8*i+:8]=kb[w*4+i];
        key_valid=1; key_data=d; key_last=(w==nw-1);
        #4; while(!key_ready) begin @(negedge clk); #4; end
        @(negedge clk); key_valid=0; key_last=0;
      end
      if(pass==0) begin
        nw=pl/4;
        for(w=0;w<nw;w=w+1) begin
          while($random & 1) @(negedge clk);
          d=0; for(i=0;i<4;i=i+1) d[8*i+:8]=mb[w*4+i];
          msg_valid=1; msg_data=d; msg_last=(w==nw-1);
          #4; while(!msg_ready) begin @(negedge clk); #4; end
          @(negedge clk); msg_valid=0; msg_last=0;
        end
      end
    end
    // out
    got=0;
    while(got<dl/4) begin
      out_ready=$random; #4;
      if(out_valid&&out_ready) begin
        for(i=0;i<4;i=i+1) gb[got*4+i]=out_data[8*i+:8];
        if(out_last !== (got==dl/4-1)) begin errs=errs+1; $display("last flag wrong t=%0d",t); end
        got=got+1;
      end
      @(negedge clk);
    end
    out_ready=0;
    for(i=0;i<dl;i=i+1) if(gb[i]!==eb[i]) begin errs=errs+1; i=dl+1; $display("MISMATCH t=%0d mode=%0d klen=%0d mlen=%0d",t,m,kl,ml); end
  end end
  $display("%s: %0d tests, %0d errors",(errs==0)?"PASS":"FAIL",n,errs); $finish;
 end
 always @(posedge clk) begin wd<=wd+1; if(wd>50000) begin $display("FAIL: STUCK (no progress for 50000 cycles) in test %0d -- check vector file / DUT version",tcur); $finish; end end
endmodule