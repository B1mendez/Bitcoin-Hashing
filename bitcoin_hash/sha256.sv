// SHA256_MODULE
module sha256   (input  logic clk,  reset_n, start,
   			  input  logic [ 3:0] sha_state,
   			  input  logic [31:0] sha_rand_num,
   			  input  logic [31:0] mem_read_data,
   			  output logic [31:0] hashout);
   			 
   					 
enum logic [3:0] {IDLE,READ1,READ2,PRECOMP,PHASE1,PHASE2,PHASE3,COMPUTE,WRITE} state;

logic [31:0] w[16];
logic [31:0] fh[8]; //final hash from test bench
logic [31:0] a, b, c, d, e, f, g, h, new_h;
logic [ 7:0] i;
logic [31:0] temp[8];
logic [ 1:0] phase_cnt;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

// SHA256 hash round -- optimization new_h = w+k+h
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, new_h);
	logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
	S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
	ch = (e & f) ^ ((~e) & g);
	t1 = S1 + ch + new_h;
	S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
	maj = (a & b) ^ (a & c) ^ (b & c);
	t2 = S0 + maj;

	sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

// right rotation
function logic [31:0] rightrotate(input logic [31:0] x,
                              	input logic [7:0] r);
begin
	rightrotate = (x >> r) | (x << (32-r));
end
endfunction


//function to compute new Wt
function logic [31:0] wtnew();
    logic [31:0] s0, s1;
    s0 = rightrotate(w[1],7)^rightrotate(w[1],18)^(w[1]>>3);
    s1 = rightrotate(w[14],17)^rightrotate(w[14],19)^(w[14]>>10);
    wtnew = w[0] + s0 + w[9] + s1;
endfunction


always@(posedge clk, negedge reset_n)
begin
    if(!reset_n) begin
   		 
    end else begin
    case(sha_state)
   	 IDLE: begin
   		 if(start) begin
   		 
   			 fh[0] <= 32'h6a09e667;
   			 fh[1] <= 32'hbb67ae85;
   			 fh[2] <= 32'h3c6ef372;
   			 fh[3] <= 32'ha54ff53a;
   			 fh[4] <= 32'h510e527f;
   			 fh[5] <= 32'h9b05688c;
   			 fh[6] <= 32'h1f83d9ab;
   			 fh[7] <= 32'h5be0cd19;
   			 
   			 a <= 32'h6a09e667;
   			 b <= 32'hbb67ae85;
   			 c <= 32'h3c6ef372;
   			 d <= 32'ha54ff53a;
   			 e <= 32'h510e527f;
   			 f <= 32'h9b05688c;
   			 g <= 32'h1f83d9ab;
   			 h <= 32'h5be0cd19;
   			 
   			 phase_cnt <= 0;

   		 end
   	 end
   		 
   	 READ1: begin
   		 i <= 0;

   	 end
   			 
   	 READ2: begin
   		 w[15] <= mem_read_data;

   	 end
   			 
   	 PRECOMP: begin    
   		 new_h <= w[15] + k[i] + fh[7];
   		 w[15] <= mem_read_data;
   		 for(int n=0; n<15; n++) w[n] <= w[n + 1];
   		 i <= 1;
   	 end
   		 
   	 PHASE1: begin
   		 if (i < 15) begin
   			 w[15]<=mem_read_data;
   			 end
   		 else begin
   			 w[15] <= wtnew();
			 end
   		 for(int n=0; n<15; n++) w[n] <= w[n + 1];
   		 new_h <= w[15] + k[i] + g;
   		 {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, new_h);
   		 i <= i + 1;
   		 if(i == 64) begin
   			 phase_cnt <= phase_cnt + 1;
   		 end
   	 end    
   		 
   	 PHASE2: begin
   		 case(i)
					2:  w[15] <= sha_rand_num;
					3:  w[15] <= 32'h80000000;
					14: w[15] <= 32'd640;
			 default: 
					if (i < 2) begin
						w[15] <= mem_read_data;
					end 
					else if (i < 14) begin
						w[15] <= 32'h00000000;
					end 
					else begin
						w[15] <= wtnew();
				end
			 endcase
   		 
   		 for(int n=0; n<15; n++) w[n] <= w[n + 1];

   		 new_h <= w[15] + k[i] + g;
   		 {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, new_h);
   			 
   		 i <= i + 1;
   						 
   		 if(i == 64) begin
   			 phase_cnt <= phase_cnt + 1;
   		 
   		 end
   	 end    

   	 PHASE3: begin  				 
   		 case(i)
					7: w[15] <= 32'h80000000;
					14: w[15] <= 32'd256;
				default: w[15] <= (i < 7) ? fh[i+1] : ((i < 14) ? 32'h00000000 : wtnew());
			endcase
   			 
   		 for(int n=0; n<15; n++) w[n] <= w[n + 1];

   		 new_h <= w[15] + k[i] + g;
   		 {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, new_h);
   			 
   		 i <= i+ 1;
   				 
   		 if(i == 64) begin
   		 
   			 fh[0] <= 32'h6a09e667;
   			 fh[1] <= 32'hbb67ae85;
   			 fh[2] <= 32'h3c6ef372;
   			 fh[3] <= 32'ha54ff53a;
   			 fh[4] <= 32'h510e527f;
   			 fh[5] <= 32'h9b05688c;
   			 fh[6] <= 32'h1f83d9ab;
   			 fh[7] <= 32'h5be0cd19;
   			 
   			 phase_cnt <= phase_cnt + 1;	 
   		 end
   	 end
   		 
   	 COMPUTE: begin
   		 fh[0] <= fh[0] + a;
   		 fh[1] <= fh[1] + b;
   		 fh[2] <= fh[2] + c;
   		 fh[3] <= fh[3] + d;
   		 fh[4] <= fh[4] + e;
   		 fh[5] <= fh[5] + f;
   		 fh[6] <= fh[6] + g;
   		 fh[7] <= fh[7] + h;

   		 a <= fh[0] + a;
   		 b <= fh[1] + b;
   		 c <= fh[2] + c;
   		 d <= fh[3] + d;
   		 e <= fh[4] + e;
   		 f <= fh[5] + f;
   		 g <= fh[6] + g;
   		 h <= fh[7] + h;
   		 
   		 if(phase_cnt==2) begin
   		 
   			 a <= 32'h6a09e667;
   			 b <= 32'hbb67ae85;
   			 c <= 32'h3c6ef372;
   			 d <= 32'ha54ff53a;
   			 e <= 32'h510e527f;
   			 f <= 32'h9b05688c;
   			 g <= 32'h1f83d9ab;
   			 h <= 32'h5be0cd19;
   			 i <= 1;
   			 w[14] <= fh[0] + a;
   			 w[15] <= fh[1] + b;
   			 new_h <= k[0] + fh[0] + a + 32'h5be0cd19;
   			 
   		 end else if(phase_cnt==3) begin
   			 hashout <= fh[0] + a;
   		 end
   	 end
   	 
   	 WRITE: begin
   	 end

    endcase
    end
end
endmodule
