<?php

/*
 * BetterDreamly - Minecraft Bedrock 1.26.0 Server
 * Built on PocketMine-MP API 4 (engine: 4.26.0)
 *
 * COMPATIBILITY STUB
 * ProcessLoginTask has been superseded by ProcessLegacyLoginTask (for self-signed/offline auth)
 * and ProcessOpenIdLoginTask (for Xbox Live / OpenID auth in Bedrock 1.26.0).
 *
 * This file exists solely so that plugins referencing ProcessLoginTask by class name
 * continue to load without fatal errors. The actual implementation is in
 * ProcessLegacyLoginTask, which is aliased as ProcessLoginTask.
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\auth;

// The real implementation — ProcessLegacyLoginTask — registers this alias at the
// bottom of its file. This stub is here as a belt-and-suspenders fallback in case
// the autoloader resolves this file before ProcessLegacyLoginTask is loaded.
if(!class_exists(ProcessLoginTask::class, false)){
	class_alias(ProcessLegacyLoginTask::class, ProcessLoginTask::class, false);
}
