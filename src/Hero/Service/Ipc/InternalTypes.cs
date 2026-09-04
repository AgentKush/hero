using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Hero.Service.Ipc;

/// <summary>
/// Lets System.Text.Json see HERO's own types.
///
/// Every domain type in this codebase is <c>internal</c> with <c>init</c>-only properties, and the
/// serialiser ignores non-public members by default. The obvious alternative was a parallel set of
/// public DTOs plus mapping in both directions — roughly 350 lines that would have to be edited
/// every time a domain type gained a field, with a silent-data-loss bug waiting on every missed
/// edit.
///
/// Shipping the domain types directly is defensible here for one specific reason: both ends of
/// this pipe are the SAME BINARY. The service and the tray app are one executable launched two
/// ways, so the wire format cannot drift between them. A mismatched pair can only happen mid-
/// upgrade, and <see cref="GuardianProtocol.PipeName"/> carries a version for exactly that case.
/// This reasoning does NOT extend to a pipe with a third-party on the other end.
/// </summary>
internal static class InternalTypes
{
    internal static JsonSerializerOptions Configure(JsonSerializerOptions options)
    {
        options.TypeInfoResolver = new DefaultJsonTypeInfoResolver
        {
            Modifiers = { AddInternalProperties },
        };
        options.Converters.Add(new IpAddressConverter());

        // Enums as names, not ordinals. Numeric enums on the wire mean a reader has to count
        // declaration order to know that severity 3 is High, and — worse — inserting a value in
        // the middle silently changes what every stored ordinal means.
        options.Converters.Add(new JsonStringEnumConverter());

        return options;
    }

    /// <summary>
    /// Adds internal instance properties that can be both read and written.
    ///
    /// Get-only properties are deliberately skipped. They are all computed —
    /// <c>ProcessRecord.FileName</c>, <c>PersistenceEntry.Key</c>, <c>Snapshot.ByPid</c> — and
    /// including them would put derived data on the wire that the receiving side would then have
    /// to be trusted not to contradict. They recompute correctly from the stored fields, so the
    /// cheapest way to keep them honest is not to transmit them.
    /// </summary>
    private static void AddInternalProperties(JsonTypeInfo info)
    {
        if (info.Kind != JsonTypeInfoKind.Object) return;
        if (info.Type.Namespace?.StartsWith("Hero", StringComparison.Ordinal) != true) return;

        foreach (var property in info.Type.GetProperties(BindingFlags.Instance | BindingFlags.NonPublic))
        {
            if (property.GetMethod is null) continue;
            if (property.SetMethod is null) continue;             // computed; recomputed locally
            if (property.GetIndexParameters().Length > 0) continue;
            if (info.Properties.Any(p => p.Name == property.Name)) continue;

            // The naming policy is NOT applied automatically to properties added this way —
            // CreateJsonPropertyInfo takes the name verbatim. Left alone, the wire carried
            // camelCase for public properties and PascalCase for internal ones, which round-trips
            // perfectly between two halves that share this resolver and is baffling to anyone
            // reading the pipe. Since being readable is the reason this protocol is plain JSON,
            // the policy is applied by hand.
            string name = info.Options.PropertyNamingPolicy?.ConvertName(property.Name)
                          ?? property.Name;

            var member = info.CreateJsonPropertyInfo(property.PropertyType, name);
            member.Get = property.GetValue;
            member.Set = property.SetValue;
            info.Properties.Add(member);
        }
    }
}

/// <summary>
/// <see cref="IPAddress"/> as its text form. Without this the serialiser walks the type's own
/// members and produces an object no one can read, which then fails to round-trip.
/// </summary>
internal sealed class IpAddressConverter : JsonConverter<IPAddress?>
{
    public override IPAddress? Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null) return null;
        var text = reader.GetString();
        return IPAddress.TryParse(text, out var address) ? address : null;
    }

    public override void Write(Utf8JsonWriter writer, IPAddress? value, JsonSerializerOptions options)
    {
        if (value is null) writer.WriteNullValue();
        else writer.WriteStringValue(value.ToString());
    }
}
