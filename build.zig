const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const opts = .{ .target = target, .optimize = optimize };
    const json_mod = b.dependency("json", opts).module("json");

    const network_mod = b.dependency("network", .{}).module("network");

    const ripemd160 = b.addStaticLibrary(.{ .name = "ripemd160", .optimize = .Debug, .target = target });
    ripemd160.addCSourceFiles(.{
        .files = &.{ "lib/ripemd160.c", "lib/memzero.c" },
    });
    ripemd160.linkLibC();

    const module = b.addModule("bitzig", .{
        .root_source_file = b.path("src/bitzig.zig"),
        .imports = &.{
            .{ .name = "json", .module = json_mod },
            .{ .name = "network", .module = network_mod },
        },
    });
    module.linkLibrary(ripemd160);
    module.addIncludePath(b.path("lib"));

    const transaction_creation_example = b.addExecutable(.{
        .name = "transaction_creation",
        .root_source_file = b.path("examples/transaction_creation.zig"),
        .target = target,
        .optimize = optimize,
    });
    transaction_creation_example.root_module.addImport("bitzig", module);

    const block_validation_example = b.addExecutable(.{
        .name = "block_validation",
        .root_source_file = b.path("examples/block_validation.zig"),
        .target = target,
        .optimize = optimize,
    });
    block_validation_example.root_module.addImport("bitzig", module);

    const getting_transactions_example = b.addExecutable(.{
        .name = "getting_transactions",
        .root_source_file = b.path("examples/getting_transactions.zig"),
        .target = target,
        .optimize = optimize,
    });
    getting_transactions_example.root_module.addImport("bitzig", module);

    const transaction_creation_step = b.step("transaction-creation", "Run transaction creation example");
    transaction_creation_step.dependOn(&b.addInstallArtifact(transaction_creation_example, .{}).step);

    const block_validation_step = b.step("block-validation", "Run block validation example");
    block_validation_step.dependOn(&b.addInstallArtifact(block_validation_example, .{}).step);

    const getting_transactions_step = b.step("getting-transactions", "Run getting transactions example");
    getting_transactions_step.dependOn(&b.addInstallArtifact(getting_transactions_example, .{}).step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const tests = b.addTest(.{
        .root_source_file = b.path("src/bitzig.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests.root_module.addImport("json", json_mod);
    tests.root_module.addImport("network", network_mod);
    tests.linkLibrary(ripemd160);
    tests.addIncludePath(b.path("lib"));
    const run_tests = b.addRunArtifact(tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
