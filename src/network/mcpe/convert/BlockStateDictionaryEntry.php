<?php

/*
 * BetterDreamly - Minecraft Bedrock 1.26.0 Server
 * Built on PocketMine-MP API 4 (engine: 4.26.0)
 *
 * Backported from PocketMine-MP 5.41.1
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\convert;

use pocketmine\data\bedrock\block\BlockStateData;
use pocketmine\nbt\LittleEndianNbtSerializer;
use pocketmine\nbt\tag\CompoundTag;
use pocketmine\nbt\tag\Tag;
use pocketmine\nbt\TreeRoot;
use pocketmine\utils\Utils;
use function count;
use function ksort;
use const SORT_STRING;

/**
 * Represents a single entry in the canonical block state palette.
 * Stores the block name and its state properties in a compact binary form
 * to reduce memory usage across thousands of block states.
 *
 * Backported from PM5.41.1 - part of the new block translation system for 1.26.0.
 */
final class BlockStateDictionaryEntry{

	/**
	 * Cache of unique raw state strings to avoid storing duplicates in memory.
	 *
	 * @var string[]
	 * @phpstan-var array<string, string>
	 */
	private static array $uniqueRawStates = [];

	private string $rawStateProperties;

	/**
	 * @param Tag[] $stateProperties
	 * @phpstan-param array<string, Tag> $stateProperties
	 */
	public function __construct(
		private string $stateName,
		array $stateProperties,
		private int $meta
	){
		$rawStateProperties = self::encodeStateProperties($stateProperties);
		// Deduplicate the string in memory (many blocks share the same state set)
		$this->rawStateProperties = self::$uniqueRawStates[$rawStateProperties] ??= $rawStateProperties;
	}

	public function getStateName() : string{
		return $this->stateName;
	}

	public function getRawStateProperties() : string{
		return $this->rawStateProperties;
	}

	/**
	 * Reconstruct a full BlockStateData object from this entry.
	 * Used when the client needs the actual NBT state, not just the runtime ID.
	 */
	public function generateStateData() : BlockStateData{
		return new BlockStateData(
			$this->stateName,
			self::decodeStateProperties($this->rawStateProperties),
			BlockStateData::CURRENT_VERSION
		);
	}

	public function getMeta() : int{
		return $this->meta;
	}

	/**
	 * Decode raw binary-encoded NBT state properties back into Tag objects.
	 *
	 * @return Tag[]
	 * @phpstan-return array<string, Tag>
	 */
	public static function decodeStateProperties(string $rawProperties) : array{
		if($rawProperties === ""){
			return [];
		}
		return (new LittleEndianNbtSerializer())->read($rawProperties)->mustGetCompoundTag()->getValue();
	}

	/**
	 * Encode state properties into a compact binary form for storage/comparison.
	 *
	 * @param Tag[] $properties
	 * @phpstan-param array<string, Tag> $properties
	 */
	public static function encodeStateProperties(array $properties) : string{
		if(count($properties) === 0){
			return "";
		}
		// Sort keys for canonical comparison (same states, different insertion order = same key)
		ksort($properties, SORT_STRING);
		$tag = new CompoundTag();
		foreach(Utils::stringifyKeys($properties) as $k => $v){
			$tag->setTag($k, $v);
		}
		return (new LittleEndianNbtSerializer())->write(new TreeRoot($tag));
	}
}
