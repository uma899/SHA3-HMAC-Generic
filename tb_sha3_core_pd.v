`timescale 1ns/1ps
module tb_sha3_pd;   // processor model: pads the message itself, then streams whole blocks
 reg clk=0, rst_n=0; always #5 clk=~clk;
 reg [1:0] mode=0; reg in_valid=0; wire in_ready; reg [31:0] in_data=0; reg in_last=0; reg [2:0] in_lb=0;
 wire out_valid; reg out_ready=0; wire [31:0] out_data; wire out_last;
 sha3_core dut(clk,rst_n,mode,in_valid,in_ready,in_data,in_last,out_valid,out_ready,out_data,out_last);
 reg [7:0] mb[0:2047]; integer rb, pl; reg [7:0] eb[0:63]; reg [7:0] gb[0:63];
 integer fd,n,t,i,m,ml,dl,r,w,nw,errs=0,got,rem,stall,cyc,tot=0; reg [31:0] d;
 always @(posedge clk) cyc<=cyc+1;
 initial begin
  if(!$value$plusargs("STALL=%d",stall)) stall=0;
  fd=$fopen("sha3vec.txt","r"); r=$fscanf(fd,"%d",n);
  repeat(3) @(posedge clk); rst_n=1; @(negedge clk);
  for(t=0;t<n;t=t+1) begin
    r=$fscanf(fd,"%d %d %d",m,ml,dl);
    for(i=0;i<ml;i=i+1) begin r=$fscanf(fd,"%h",d); mb[i]=d[7:0]; end
    for(i=0;i<dl;i=i+1) begin r=$fscanf(fd,"%h",d); eb[i]=d[7:0]; end
    while(!in_ready) @(negedge clk);
    cyc=0; mode=m;
    // SHA3 padding done here (= by the processor): 0x06, zeros, 0x80 at end of last block
    rb = (m==0)?144:(m==1)?136:(m==2)?104:72;
    pl = ((ml/rb)+1)*rb;
    for(i=ml;i<pl;i=i+1) mb[i]=8'h00;
    mb[ml] = mb[ml] | 8'h06;  mb[pl-1] = mb[pl-1] | 8'h80;
    nw = pl/4;
    for(w=0;w<nw;w=w+1) begin
      if(stall) while($random & 1) @(negedge clk);
      d=0; for(i=0;i<4;i=i+1) d[8*i+:8]=mb[w*4+i];
      in_valid=1; in_data=d; in_last=(w==nw-1);
      #4; while(!in_ready) begin @(negedge clk); #4; end
      @(negedge clk); in_valid=0; in_last=0;
    end
    got=0;
    while(got<dl/4) begin
      out_ready= stall ? $random : 1; #4;
      if(out_valid&&out_ready) begin
        for(i=0;i<4;i=i+1) gb[got*4+i]=out_data[8*i+:8];
        if(out_last !== (got==dl/4-1)) begin errs=errs+1; $display("last flag wrong t=%0d",t); end
        got=got+1;
      end
      @(negedge clk);
    end
    out_ready=0; tot=tot+cyc;
    if(!stall) $display("cycles mode=%0d len=%0d : %0d",m,ml,cyc);
    for(i=0;i<dl;i=i+1) if(gb[i]!==eb[i]) begin errs=errs+1; i=dl+1; $display("MISMATCH t=%0d mode=%0d len=%0d",t,m,ml); end
  end
  $display("%s: %0d tests, %0d errors, total cycles %0d",(errs==0)?"PASS":"FAIL",n,errs,tot); $finish;
 end
 initial begin #900000000; $display("FAIL: TIMEOUT"); $finish; end
endmodule
