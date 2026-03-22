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
use pocketmine\data\bedrock\block\BlockTypeNames;
use pocketmine\nbt\NbtDataException;
use pocketmine\nbt\TreeRoot;
use pocketmine\network\mcpe\protocol\serializer\NetworkNbtSerializer;
use pocketmine\utils\Utils;
use function array_key_first;
use function array_map;
use function count;
use function get_debug_type;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;

/**
 * Lookup table from block state data (name + properties) to network runtime IDs
 * and vice versa. Used by BlockTranslator to map internal block state IDs to the
 * runtime IDs that the client understands.
 *
 * Backported from PM5.41.1 - replaces the old NBT-scan approach in RuntimeBlockMapping.
 */
final class BlockStateDictionary{

	/**
	 * Fast lookup: stateName => runtime ID (for stateless blocks)
	 *            or stateName => [rawProps => runtime ID] (for stateful blocks)
	 *
	 * @var int[][]|int[]
	 * @phpstan-var array<string, array<string, int>|int>
	 */
	private array $stateDataToStateIdLookup = [];

	/**
	 * Lazy-built reverse lookup for legacy id+meta -> runtime ID (for recipe ingredients).
	 *
	 * @var int[][]|null
	 * @phpstan-var array<string, array<int, int>|int>|null
	 */
	private ?array $idMetaToStateIdLookupCache = null;

	/**
	 * @param BlockStateDictionaryEntry[] $states
	 * @phpstan-param list<BlockStateDictionaryEntry> $states
	 */
	public function __construct(
		private array $states
	){
		$table = [];
		foreach($this->states as $stateId => $state){
			$table[$state->getStateName()][$state->getRawStateProperties()] = $stateId;
		}

		// Optimise: stateless blocks get an int directly (avoids an array lookup per call)
		foreach(Utils::stringifyKeys($table) as $name => $stateIds){
			if(count($stateIds) === 1){
				$this->stateDataToStateIdLookup[$name] = $stateIds[array_key_first($stateIds)];
			}else{
				$this->stateDataToStateIdLookup[$name] = $stateIds;
			}
		}
	}

	/**
	 * @return int[][]
	 * @phpstan-return array<string, array<int, int>|int>
	 */
	private function getIdMetaToStateIdLookup() : array{
		if($this->idMetaToStateIdLookupCache === null){
			$table = [];
			foreach($this->states as $i => $state){
				$table[$state->getStateName()][$state->getMeta()] = $i;
			}

			$this->idMetaToStateIdLookupCache = [];
			foreach(Utils::stringifyKeys($table) as $name => $metaToStateId){
				if(count($metaToStateId) === 1){
					$this->idMetaToStateIdLookupCache[$name] = $metaToStateId[array_key_first($metaToStateId)];
				}else{
					$this->idMetaToStateIdLookupCache[$name] = $metaToStateId;
				}
			}
		}

		return $this->idMetaToStateIdLookupCache;
	}

	/**
	 * Returns the BlockStateData for the given runtime ID, or null if not found.
	 */
	public function generateDataFromStateId(int $networkRuntimeId) : ?BlockStateData{
		return ($this->states[$networkRuntimeId] ?? null)?->generateStateData();
	}

	/**
	 * Looks up the runtime ID that matches the given BlockStateData.
	 * Returns null if no match is found.
	 */
	public function lookupStateIdFromData(BlockStateData $data) : ?int{
		$name   = $data->getName();
		$lookup = $this->stateDataToStateIdLookup[$name] ?? null;

		return match(true){
			$lookup === null  => null,
			is_int($lookup)   => $lookup,
			is_array($lookup) => $lookup[BlockStateDictionaryEntry::encodeStateProperties($data->getStates())] ?? null,
		};
	}

	/**
	 * Returns the legacy meta value associated with a network runtime ID.
	 * Used when serializing crafting recipe inputs.
	 */
	public function getMetaFromStateId(int $networkRuntimeId) : ?int{
		return ($this->states[$networkRuntimeId] ?? null)?->getMeta();
	}

	/**
	 * Looks up a runtime ID by legacy block ID + meta.
	 * Used when deserializing crafting recipe inputs.
	 */
	public function lookupStateIdFromIdMeta(string $id, int $meta) : ?int{
		$metas = $this->getIdMetaToStateIdLookup()[$id] ?? null;

		return match(true){
			$metas === null  => null,
			is_int($metas)   => $metas,
			is_array($metas) => $metas[$meta] ?? null,
		};
	}

	/**
	 * @return BlockStateDictionaryEntry[]
	 * @phpstan-return array<int, BlockStateDictionaryEntry>
	 */
	public function getStates() : array{
		return $this->states;
	}

	/**
	 * Parse the canonical block palette NBT into a list of BlockStateData objects.
	 *
	 * @return BlockStateData[]
	 * @phpstan-return list<BlockStateData>
	 * @throws NbtDataException
	 */
	public static function loadPaletteFromString(string $blockPaletteContents) : array{
		return array_map(
			fn(TreeRoot $root) => BlockStateData::fromNbt($root->mustGetCompoundTag()),
			(new NetworkNbtSerializer())->readMultiple($blockPaletteContents)
		);
	}

	/**
	 * Build a BlockStateDictionary from the canonical NBT palette and its
	 * associated meta map (JSON array mapping palette index -> legacy meta).
	 *
	 * @throws \InvalidArgumentException on malformed data
	 */
	public static function loadFromString(string $blockPaletteContents, string $metaMapContents) : self{
		$metaMap = json_decode($metaMapContents, flags: JSON_THROW_ON_ERROR);
		if(!is_array($metaMap)){
			throw new \InvalidArgumentException(
				"Invalid metaMap, expected array, got " . get_debug_type($metaMap)
			);
		}

		$entries = [];

		// Pre-intern known block names for memory efficiency
		$uniqueNames = [];
		foreach((new \ReflectionClass(BlockTypeNames::class))->getConstants() as $value){
			if(is_string($value)){
				$uniqueNames[$value] = $value;
			}
		}

		foreach(self::loadPaletteFromString($blockPaletteContents) as $i => $state){
			$meta = $metaMap[$i] ?? null;
			if($meta === null){
				throw new \InvalidArgumentException(
					"Missing meta value for palette entry $i (" . $state->toNbt() . ")"
				);
			}
			if(!is_int($meta)){
				throw new \InvalidArgumentException(
					"Invalid meta value for palette entry $i: expected int, got " . get_debug_type($meta)
				);
			}
			$uniqueName  = $uniqueNames[$state->getName()] ??= $state->getName();
			$entries[$i] = new BlockStateDictionaryEntry($uniqueName, $state->getStates(), $meta);
		}

		return new self($entries);
	}
}
