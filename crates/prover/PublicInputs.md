public_inputs[0]：后128位是header的sha256的前128位。前128位是“email_header_data_len”，代表header在padding后做sha256的长度。
public_inputs[1]：后128位是header的sha256的后128位。前128位是“mask_hash_len”，代表sha256(a_hash|b_hash)的长度，这个值可以改掉在电路里直接约束为常数2不用作为public_input。
public_inputs[2]：后128位是address的sha256的前128位。前128位是“email_addr_pepper_data_len”，代表address在padding后做sha256的长度。
public_inputs[3]：后128位是address的sha256的后128位。前128位是“0。
1024电路：
public_inputs[4..=8]：是隐私匹配中，header对应的“0/1 mask串”，需要1024个bit，只在address位置的bit为1，其它应该为0。每个public_inputs的后252位用来放置这1024个bit，所以会占5个public_inputs。
public_inputs[9]：是隐私匹配中，address对应的“0/1 mask串”，需要192个bit，所以只需一个public_inputs。也就是说后192位中的前x个bit应该为1，其它应该为0。
public_inputs[10]：后128位是“公开匹配字符串”的sha256的前128位。前128位是0。
public_inputs[11]：后128位是“公开匹配字符串”的sha256的后128位。前128位是0。
2048电路：
public_inputs[4..=12]：是隐私匹配中，header对应的“0/1 mask串”，需要2048个bit，只在address位置的bit为1，其它应该为0。每个public_inputs的后252位用来放置这2048个bit，所以会占9个public_inputs。
public_inputs[13]：是隐私匹配中，address对应的“0/1 mask串”，需要192个bit，所以只需一个public_inputs。也就是说后192位中的前x个bit应该为1，其它应该为0。
public_inputs[14]：后128位是“公开匹配字符串”的sha256的前128位。前128位是0。
public_inputs[15]：后128位是“公开匹配字符串”的sha256的后128位。前128位是0。