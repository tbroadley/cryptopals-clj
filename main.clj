; Set 1 Challenge 1

(def s1c1-input "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
(def s1c1-output "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

(defn from-hex
  ([hex] (map (fn [x] x) (.toByteArray (BigInteger. hex 16)))))

(defn to-base64
  ([ba] (.encodeToString (java.util.Base64/getEncoder) (byte-array ba))))

(defn base64-from-hex
  ([hex] (to-base64 (from-hex hex))))

(assert (= (base64-from-hex s1c1-input) s1c1-output))

; Set 1 Challenge 2

(def s1c2-input1 "1c0111001f010100061a024b53535009181c")
(def s1c2-input2 "686974207468652062756c6c277320657965")
(def s1c2-output "746865206b696420646f6e277420706c6179")

(defn xor
  ([ba1 ba2] (map bit-xor ba1 ba2)))

(assert (= (xor (from-hex s1c2-input1) (from-hex s1c2-input2))
           (map (fn [x] x) (from-hex s1c2-output))))

; Set 1 Challenge 3

(def s1c3-input "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

(def character-frequencies {
  "a" 8.34,
  "b" 1.54,
  "c" 2.73,
  "d" 4.14,
  "e" 12.60,
  "f" 2.03,
  "g" 1.92,
  "h" 6.11,
  "i" 6.71,
  "j" 0.23,
  "k" 0.87,
  "l" 4.24,
  "m" 2.53,
  "n" 6.80,
  "o" 7.70,
  "p" 1.66,
  "q" 0.09,
  "r" 5.68,
  "s" 6.11,
  "t" 9.37,
  "u" 2.85,
  "v" 1.06,
  "w" 4.34,
  "x" 0.20,
  "y" 2.04,
  "z" 0.06,

  "A" 8.34,
  "B" 1.54,
  "C" 2.73,
  "D" 4.14,
  "E" 12.60,
  "F" 2.03,
  "G" 1.92,
  "H" 6.11,
  "I" 6.71,
  "J" 0.23,
  "K" 0.87,
  "L" 4.24,
  "M" 2.53,
  "N" 6.80,
  "O" 7.70,
  "P" 1.66,
  "Q" 0.09,
  "R" 5.68,
  "S" 6.11,
  "T" 9.37,
  "U" 2.85,
  "V" 1.06,
  "W" 4.34,
  "X" 0.20,
  "Y" 2.04,
  "Z" 0.06,
})

(defn abs ([x] (max x (- x))))

(defn to-utf8 ([b] (String. (byte-array b) "UTF-8")))

(defn dsbx-helper1
  ([ciphertext b]
    (let [len (count ciphertext)
          candidate-key (repeat (count ciphertext) b)]
      (xor candidate-key ciphertext))))

(defn dsbx-helper2
  ([candidate-plaintext]
    (let [freqs (frequencies candidate-plaintext)
          f-keys (map #(to-utf8 (list %)) (keys freqs))
          f-vals (map #(/ % (count candidate-plaintext)) (vals freqs))
          div-freqs (zipmap f-keys f-vals)
          freq-diffs (map #(abs (- (/ (get character-frequencies % 0) 100) (get div-freqs %))) f-keys)]
      (reduce (fn [a b] (+ a b)) freq-diffs))))

(defn decrypt-single-byte-xor
  ([ciphertext]
    (let [candidate-bytes (range 128)
          candidate-plaintexts (map #(dsbx-helper1 ciphertext %) candidate-bytes)
          freq-diffs (map dsbx-helper2 candidate-plaintexts)
          freq-order (sort-by #(nth freq-diffs %) candidate-bytes)]
      (first (map #(nth candidate-plaintexts %) freq-order)))))

(assert (= (to-utf8 (decrypt-single-byte-xor (from-hex s1c3-input))) "Cooking MC's like a pound of bacon"))
