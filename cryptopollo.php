<?php

class CryptoPollo {
    private $blockSize = 16;
    private $keySize = 16;
    private $key;
    private $iv;
    private $numRounds;

    public function __construct(string $key, string $iv, int $numRounds = 10) {
        if (strlen($key) !== $this->keySize) {
            throw new Exception("Key must be exactly {$this->keySize} bytes.");
        }
        if (strlen($iv) !== $this->blockSize) {
            throw new Exception("IV must be exactly {$this->blockSize} bytes.");
        }
        $this->key = $key;
        $this->iv = $iv;
        $this->numRounds = $numRounds;
    }

    private function deriveSBox(string $seed): array {
        $hash = hash('sha256', $seed, true);
        $sbox = range(0, 255);
        mt_srand(unpack('N', $hash)[1]);
        shuffle($sbox);
        return $sbox;
    }

    private function deriveInvSBox(array $sbox): array {
        $invSBox = array_fill(0, 256, 0);
        foreach ($sbox as $i => $value) {
            $invSBox[$value] = $i;
        }
        return $invSBox;
    }

    private function subBytes(array $data, array $sbox): array {
        return array_map(fn($byte) => $sbox[$byte], $data);
    }

    private function invSubBytes(array $data, array $invSBox): array {
        return array_map(fn($byte) => $invSBox[$byte], $data);
    }

    private function shiftRows(array $data): array {
        return array_merge(array_slice($data, 1), array_slice($data, 0, 1));
    }

    private function invShiftRows(array $data): array {
        return array_merge(array_slice($data, -1), array_slice($data, 0, -1));
    }

    private function mixColumns(array $data): array {
        return array_map(function($byte, $i) {
            return $byte ^ ord($this->key[$i % $this->keySize]);
        }, $data, array_keys($data));
    }

    private function invMixColumns(array $data): array {
        return $this->mixColumns($data); // XOR is its own inverse
    }

    private function addPadding(string $data): string {
        $paddingLen = $this->blockSize - (strlen($data) % $this->blockSize);
        return $data . str_repeat(chr($paddingLen), $paddingLen);
    }

    private function removePadding(string $data): string {
        $paddingLen = ord($data[strlen($data) - 1]);
        return substr($data, 0, -$paddingLen);
    }

    private function encryptBlock(array $block, array $sbox): array {
        $state = $block;
        for ($round = 0; $round < $this->numRounds; $round++) {
            $state = $this->subBytes($state, $sbox);
            $state = $this->shiftRows($state);
            $state = $this->mixColumns($state);
        }
        return $state;
    }

    private function decryptBlock(array $block, array $invSBox): array {
        $state = $block;
        for ($round = 0; $round < $this->numRounds; $round++) {
            $state = $this->invMixColumns($state);
            $state = $this->invShiftRows($state);
            $state = $this->invSubBytes($state, $invSBox);
        }
        return $state;
    }

    public function encrypt(string $plaintext): string {
        $plaintext = $this->addPadding($plaintext);
        $encryptedBlocks = [];
        $previousBlock = array_map('ord', str_split($this->iv, 1));

        foreach (str_split($plaintext, $this->blockSize) as $block) {
            $block = array_map('ord', str_split($block, 1));
            $xoredBlock = array_map(fn($byte, $prev) => $byte ^ $prev, $block, $previousBlock);
            $seed = implode('', array_map('chr', $previousBlock)) . $this->key;
            $sbox = $this->deriveSBox($seed);
            $encryptedBlock = $this->encryptBlock($xoredBlock, $sbox);
            $encryptedBlocks[] = implode('', array_map('chr', $encryptedBlock));
            $previousBlock = $encryptedBlock;
        }

        return $this->iv . implode('', $encryptedBlocks);
    }

    public function decrypt(string $ciphertext): string {
        $iv = substr($ciphertext, 0, $this->blockSize);
        $ciphertext = substr($ciphertext, $this->blockSize);
        $decryptedData = '';
        $previousBlock = array_map('ord', str_split($iv, 1));

        foreach (str_split($ciphertext, $this->blockSize) as $block) {
            $block = array_map('ord', str_split($block, 1));
            $seed = implode('', array_map('chr', $previousBlock)) . $this->key;
            $sbox = $this->deriveSBox($seed);
            $invSBox = $this->deriveInvSBox($sbox);
            $decryptedBlock = $this->decryptBlock($block, $invSBox);
            $xoredBlock = array_map(fn($byte, $prev) => $byte ^ $prev, $decryptedBlock, $previousBlock);
            $decryptedData .= implode('', array_map('chr', $xoredBlock));
            $previousBlock = $block;
        }

        return $this->removePadding($decryptedData);
    }
}

