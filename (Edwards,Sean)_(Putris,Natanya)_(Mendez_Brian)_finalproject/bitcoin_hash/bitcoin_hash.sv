//`include "sha256.sv"
module bitcoin_hash(input  logic clk, reset_n, start,
   				 input  logic [15:0] message_addr, output_addr,
   				 output logic done,
   				 output logic mem_clk, mem_we,
   				 output logic [15:0] mem_addr,
   				 output logic [31:0] mem_write_data,
   				 input  logic [31:0] mem_read_data);

enum logic [3:0] {IDLE,
   					 READ1,
   					 READ2,
   					 PRECOMP,
   					 PHASE1,     
   					 PHASE2,
   					 PHASE3,
   					 COMPUTE,
   					 WRITE } state;
   					 
assign mem_clk = clk;

parameter NUM_NONCES = 16;

parameter int rand_num[0:15] = '{32'd0,32'd1,32'd2,32'd3,32'd4,32'd5,32'd6,32'd7,
   									 32'd8,32'd9,32'd10,32'd11,32'd12,32'd13,32'd14,32'd15};
logic [ 7:0] i;
logic [31:0] h[16];
logic [15:0] offset;
logic [15:0] write_offset;
logic [ 1:0] phase_cnt;


genvar q;
generate
    for (q=0; q<NUM_NONCES; q++) begin : generate_sha256_modules
   		 sha256 sha256_inst (
   		 .clk(clk),
   		 .reset_n(reset_n),
   		 .sha_state(state),
   		 .start(start),
   		 .sha_rand_num(rand_num[q]),
   		 .mem_read_data(mem_read_data),
   		 .hashout(h[q]));
   		 end
endgenerate

always@(posedge clk, negedge reset_n)
begin
    if(!reset_n) begin
   	 done <= 0;
   	 offset <= 0;
   	 write_offset<=0;
   	 state <= IDLE;
    end
    else begin
   	 case(state)
   		 IDLE: begin
   			 if(start) begin
   				 phase_cnt <= 0;
   				 mem_we <= 0;
   				 mem_addr <= message_addr + offset;
   				 offset <= offset + 1;    
   				 state <= READ1;
   				 end
   			 end
   			 
   		 READ1: begin
   			 i <= 0;
   			 mem_addr <= message_addr + offset;
   			 offset <=offset + 1;   	 
   			 state <= READ2;
   			 end
   				 
   		 READ2: begin
   			 mem_addr <= message_addr + offset;
   			 offset <= offset + 1;
   			 state <= PRECOMP;
   			 end
   				 
   		 PRECOMP: begin
   			 mem_addr <= message_addr + offset;
   			 offset <= offset + 1;
   			 i <= 1;

   			 if(phase_cnt == 1) begin
   				 state <= PHASE2;
   				 end
   			 else begin
   				 state <= PHASE1;
   				 end
   			 end
   			 
   		 PHASE1: begin
   			 if (i < 15) begin
   				 mem_addr <= message_addr + offset;
   				 offset <= offset + 1;
   				 end
   			 i <= i + 1;
   			 if(i == 64) begin
   				 phase_cnt <= phase_cnt + 1;
   				 state<=COMPUTE;
   				 end
   			 else begin
   				 state<=PHASE1;
   				 end
   			 end    
   			 
   		 PHASE2: begin
   			 if (i < 2) begin
   				 mem_addr <= message_addr + offset;
   				 offset <= offset + 1;
   				 end
   			 i <= i + 1;
   			 if(i == 64) begin
   				 phase_cnt <= phase_cnt + 1;
   				 state<=COMPUTE;
   				 end
   			 else begin
   				 state<=PHASE2;
   				 end
   			 end    

   		 PHASE3: begin
   			 i <= i + 1;
   			 if(i == 64) begin
   				 phase_cnt <= phase_cnt + 1;
   				 mem_addr <= message_addr + 16;
   				 offset <= 17;
   				 state<=COMPUTE;
   				 end
   			 else begin
   				 state<=PHASE3;
   				 end
   			 end
   			 
   		 COMPUTE: begin   		 
   			 if(phase_cnt == 1) begin
   				 mem_addr <= message_addr + 16;
   				 offset <= 17;
   				 state<=READ1;
   				 
   				 end
   			 else if(phase_cnt==2) begin
   				 i <= 1;
   				 state <= PHASE3;
   				 
   				 end
   			 else if(phase_cnt==3) begin
   				 i <= 0;
   				 state <= WRITE;
   				 end    
   			 end
   		 
   		 WRITE: begin
   			 mem_we <= 1;
   			 mem_addr <= output_addr + write_offset;
   			 mem_write_data <= h[i];
   			 i <= i + 1;
   			 write_offset <= write_offset + 1;
   			 if(write_offset == 16) begin
   				 done<=1;
   				 end
   			 else begin
   				 state<= WRITE;
   				 end
   			 end
   		 endcase
   	 end
    end
endmodule
