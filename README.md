# TCP/IP Protocol Stack with Go (Self-Learning Project)

This repository is a personal, hands-on learning project created to understand computer networking protocols from the ground up. It contains an experimental implementation of core TCP/IP stack components, gradually built layer-by-layer from Data Link (Ethernet) up to Transport (TCP).

**Disclaimer**: This project is strictly for educational and self-study purposes. It is **not** a production-grade software or intended for commercial use.

---

## Goals

The primary goal of this project is to demystify how networks operate underneath by working directly with raw byte structures, headers, and state machines.

Through this experiment, I aim to gain a deeper practical understanding of:
- How raw binary packets are framed, decoded, and transmitted across layers.
- Header structures and field bitmasks (Ethernet, IPv4, TCP).
- Network algorithms, such as internet checksum calculations (RFC 1071) and endianness handling.
- Connection state management and packet processing flow.

---

## Architecture & Progress

The implementation follows a bottom-up layered approach:

### 1. Data Link Layer (L2)
- [x] Ethernet frame parsing and construction.
- [x] MAC address handling and EtherType identification.

### 2. Network Layer (L3)
- [x] IPv4 header construction and payload decoding.
- [x] Internet Checksum implementation (One's Complement Sum).
- [x] Basic ICMP handling (Echo Request / Reply).

### 3. Transport Layer (L4) *(In Progress)*
- [x] UDP header parsing and checksum verification with pseudo-header.
- [ ] TCP segment structure parsing and byte-level manipulation.
- [ ] Basic connection state handling (SYN, SYN-ACK, ACK sequence flow).
- [ ] Retransmission and window management.

---

## References & Inspiration

This project relies on knowledge and inspiration gathered from various open-source resources, network documentation, and community tutorials, including:

- **RFC Documentation**: RFC 791 (IPv4), RFC 793 (TCP), RFC 1071 (Internet Checksum).
- Various online articles, open-source network stacks, and technical blogs focusing on raw socket manipulation and low-level protocol development.

---

## License

Feel free to use, modify, or inspect this codebase for your own learning and exploration purposes.
