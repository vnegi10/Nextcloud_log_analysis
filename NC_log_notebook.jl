### A Pluto.jl notebook ###
# v0.20.4

using Markdown
using InteractiveUtils

# ╔═╡ f87b8466-dc05-11ef-2c7f-6585551df9a1
using JSON,
      DataFrames,
      Dates,
      HTTP,
      JSON3,
      CSV,
      Sockets

# ╔═╡ 4d81e853-e592-40c0-a66a-f5fa11467fe9
md"""
### Read input
"""

# ╔═╡ 15e06b0a-13de-4d70-99aa-f870b3b07732
fname_1 = joinpath(@__DIR__, "nextcloud.log.json")

# ╔═╡ 2ffc741b-09c2-4e44-a190-f187a0a7b6cd
#all_lines = readlines(fname)

# ╔═╡ f56b519f-df0f-442d-835a-e4c8aa94af1f
md"""
### Parse to DataFrame
"""

# ╔═╡ 5d72dcbb-c814-4ed5-b9dd-0ba3cdf27b9d
function log_to_df(fname, filter_string, dict_field)

	all_dict = []

	open(fname, "r") do file
		for line in eachline(file)
			try
				line_dict = JSON.parse(line)
				if occursin(filter_string, line_dict[dict_field])
		            push!(all_dict, line_dict)
				end
		    catch
			    continue
			end
		end		
	end

	# Nested dicts cause problems when converting to a DataFrame
	for each_dict in all_dict
		if haskey(each_dict, "exception")
			delete!(each_dict, "exception")
		end
	end

	df = DataFrame[]

	if ~isempty(all_dict)
		df = DataFrame(vcat(all_dict...))

		# Parse the timestamp column into DateTime objects
		df.time = DateTime.(df.time, "yyyy-mm-ddTHH:MM:SS+00:00")
	end
	
	return df

end

# ╔═╡ 0bd70285-6df7-467b-ac34-942d553679dd
md"""
### Check for failed logins
"""

# ╔═╡ 69290ffd-6841-46f0-b927-6314406e5758
#df_log_failed = log_to_df(fname_1, "Login failed", "message")

# ╔═╡ f3a15dca-a3be-4a43-976d-e1894ee7e19d
# # Find the minimum and maximum dates
# (
#     minimum(df_log_failed.time),
#     maximum(df_log_failed.time)
# )

# ╔═╡ 91015ec6-05ce-4451-b546-a7da73643dc7
md"""
#### Filter based on user id
"""

# ╔═╡ 137080b5-3c45-4a66-8812-ba52b64bb777
# df_failed = filter(row -> ~(occursin("vnegi10", row.message) | 
#                             occursin("mdash", row.message)),
# 	                          df_log_failed)

# ╔═╡ 3e15aa11-084e-404d-a0c0-4078ef9e5f8b
md"""
### Check for domain
"""

# ╔═╡ 53533056-c888-4e63-8844-24cefdc67007
df_domain = log_to_df(fname_1, "Trusted domain error", "message");

# ╔═╡ 71fbc64b-ca35-4129-a182-95a43deae8db
# Find the minimum and maximum dates
(
    minimum(df_domain.time),
    maximum(df_domain.time)
)

# ╔═╡ 42bc870d-8e98-4d09-b5f8-d3b44e0326b1
rows, cols = size(df_domain)

# ╔═╡ 843b32ef-d77f-483c-b4e6-6e9e5ab78290
df_domain.userAgent |> unique

# ╔═╡ 4a613851-178f-4bd9-8a07-26e9911f49db
md"""
#### Count unique ip addresses
"""

# ╔═╡ a64e8d78-ca5e-43e6-bc23-05b074175536
function get_count(df_domain, filter_string, gby_cols)

	df_domain_filter = filter(row -> (occursin(filter_string, 
		                                        row.userAgent)), df_domain) 

	df_counts = combine(groupby(df_domain_filter, 
		                        gby_cols), 
		                        nrow => :count)
	
	return sort(df_counts, :count, rev = true)

end	

# ╔═╡ df53fd12-1e37-4f3e-9af4-2bddbc6dc477
#get_count(df_domain, [:remoteAddr])

# ╔═╡ 1d9bbec8-3930-484f-9922-10d3f4ce96c0
#get_count(df_domain, [:userAgent])

# ╔═╡ 8e99afc7-aa99-4ce5-9d45-a77492f0c412
df_count = get_count(df_domain, "Macintosh", [:remoteAddr])

# ╔═╡ 40f83181-b9ff-4cfc-b439-d0027a215cd0
md"""
### Geolocate IP
"""

# ╔═╡ cf972491-7e57-4ed1-b04a-87db52568117
md"""
#### Fetch using API
"""

# ╔═╡ c433e976-0b1a-4aa7-9b12-52b257a9047d
function get_geolocation(ip::String)
	
    url = "http://ip-api.com/json/$ip"
	data = nothing

	try
		response = HTTP.get(url)
        data = JSON3.read(response.body)
	catch e
		if isa(e, HTTP.ExceptionRequest.StatusError)
            error("Check if the input is valid")
        else
            error("Could not fetch data for $(ip), try again later!")
        end		
	end

    return data
	
end

# ╔═╡ f94c0aca-14f8-480b-864d-bd5a72398a3f
#get_geolocation("115.159.220.67")

# ╔═╡ 22ae387b-abe6-4349-bfcd-97f28bdb00f4
function ip_api_to_geo_df(df_count_filter::DataFrame)

	all_ips = df_count_filter[!, :remoteAddr]
	geo_dicts = []

	for ip in all_ips
		try
			geo_dict = get_geolocation(ip)
			push!(geo_dicts, geo_dict)
		catch
			# Rate limit of 45 requests per second
			@info "Rate limit of 45 requests per second reached!"
			break
		end
	end

	df = DataFrame(vcat(geo_dicts...))

	return df

end

# ╔═╡ b312253b-4322-4f56-96b7-87ef34702ee8
md"""
#### Merge with count data
"""

# ╔═╡ 65e31759-efb9-426a-b49e-4d8ad4d3a01f
function geo_join_ip_api(df_count::DataFrame)

	df_geo = ip_api_to_geo_df(df_count)
	
	df_geo_join = leftjoin(df_geo,
		                   df_count,
		                   on = :query => :remoteAddr)
	
	rename!(df_geo_join, Dict(:count => "count_ips"))

	return df_geo_join

end

# ╔═╡ f573d1f1-f359-4ef9-8822-337ea58d7938
#df_geo_api = geo_join_ip_api(df_count)

# ╔═╡ 280be0cd-228c-42cb-a65a-1f717c98ceb6
md"""
#### Read IP database
"""

# ╔═╡ 4f0aa43d-4e7a-4ea0-82cb-05197cba68bb
function ip_csv_to_df(fname::String)	

	df_ip = CSV.read(fname, DataFrame;
		              header = [:ip_start, 
					            :ip_end,
						        :continent,
					            :country,
					            :stateprov,
					            :city,
						        :latitude,
						        :longitude				  
					           ],
		              select = [:ip_start, 
					            :ip_end,
					            :country,
					            :stateprov,
					            :city
					           ],
		             missingstring = ""
	                 )

	# Filter out ipv4 addresses
	df_ipv4 = filter(row -> occursin(".", 
		                             row.ip_start), df_ip)

	# # Filter out ipv6 addresses
	# df_ipv6 = filter(row -> occursin(":", 
	# 	                             row.ip_start), df_ip)

	# Convert to types provided by Sockets
	df_ipv4.ip_start = UInt32.(IPv4.(df_ipv4.ip_start))
	df_ipv4.ip_end = UInt32.(IPv4.(df_ipv4.ip_end))

	# df_ipv6.ip_start = IPv6.(df_ipv6.ip_start)
	# df_ipv6.ip_end = IPv6.(df_ipv6.ip_end)	

	return df_ipv4
end	

# ╔═╡ 872d359e-c013-4f72-a569-867d3fa3805d
#df_ipv4 = ip_csv_to_df("dbip-city-lite-2025-02.csv")

# ╔═╡ b0070a92-10fc-4610-86eb-a33fa2d9b96a
md"""
#### Merge with IP database
"""

# ╔═╡ 6b605489-2e10-4d80-8160-7913ce8c5661
function geo_join_ip_db(df_count::DataFrame)

	df_ipv4 = ip_csv_to_df("dbip-city-lite-2025-02.csv")

	all_ips = df_count[!, :remoteAddr]
	all_matches = DataFrame[]
	found_ips = String[]

	for ip in all_ips
		ip_int = ip |> IPv4 |> UInt32
		df_match = filter(row -> row.ip_start ≤ ip_int ≤ row.ip_end, df_ipv4)

		if ~isempty(df_match)
			push!(all_matches, select(df_match,
				                      :country,
				                      :stateprov,
				                      :city			
			                          )
			      )
			push!(found_ips, ip)
		end
	end

	df_all = DataFrame(vcat(all_matches...))

	insertcols!(df_all, 1, :remoteAddr => found_ips)	
	
	return df_all

end

# ╔═╡ 31a396b8-c218-4776-8790-51bf5162f6f1
#@time df_geo_db = geo_join_ip_db(df_count)

# ╔═╡ d6453d94-9580-4146-86f9-0511143487a3
function geo_join_ip_db_opt(df_count::DataFrame)

	df_ipv4 = ip_csv_to_df("dbip-city-lite-2025-02.csv")
	
	# Sort IP database for binary search speedup
    sort!(df_ipv4, :ip_start)

	all_ips = df_count[!, :remoteAddr]
	all_matches = DataFrame[]
	found_ips = String[]

	for ip in all_ips

		ip_int = ip |> IPv4 |> UInt32

		idx = searchsortedfirst(df_ipv4[!, :ip_start], ip_int)
		df_match = DataFrame()

		if idx ≤ nrow(df_ipv4)
			# Match is found where ip_int == ip_start at idx
			if df_ipv4[idx, :ip_start] ≤ ip_int ≤ df_ipv4[idx, :ip_end]
				df_match = df_ipv4[idx:idx, :]
			# No match --> Look at previous index
			else
				df_match = df_ipv4[idx-1:idx-1, :]
			end
		end

		if ~isempty(df_match)		
			push!(all_matches, select(df_match,
									  :country,
									  :stateprov,
									  :city			
									  )
				 )
			push!(found_ips, ip)
		end
		
	end

	df_all = DataFrame(vcat(all_matches...))

	insertcols!(df_all, 1, :remoteAddr => found_ips)

	df_all_join = leftjoin(df_all,
		                   df_count,
		                   on = :remoteAddr)
	
	return df_all_join

end

# ╔═╡ 2fa4826b-8c4a-4c1c-b7d6-571af1753459
@time df_geo_db_opt = geo_join_ip_db_opt(df_count)

# ╔═╡ 00000000-0000-0000-0000-000000000001
PLUTO_PROJECT_TOML_CONTENTS = """
[deps]
CSV = "336ed68f-0bac-5ca0-87d4-7b16caf5d00b"
DataFrames = "a93c6f00-e57d-5684-b7b6-d8193f3e46c0"
Dates = "ade2ca70-3891-5945-98fb-dc099432e06a"
HTTP = "cd3eb016-35fb-5094-929b-558a96fad6f3"
JSON = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
JSON3 = "0f8b85d8-7281-11e9-16c2-39a750bddbf1"
Sockets = "6462fe0b-24de-5631-8697-dd941f90decc"

[compat]
CSV = "~0.10.15"
DataFrames = "~1.7.0"
HTTP = "~1.10.15"
JSON = "~0.21.4"
JSON3 = "~1.14.0"
"""

# ╔═╡ 00000000-0000-0000-0000-000000000002
PLUTO_MANIFEST_TOML_CONTENTS = """
# This file is machine-generated - editing it directly is not advised

julia_version = "1.11.3"
manifest_format = "2.0"
project_hash = "6fdf25667d3140c8ffe3b21a9617b6e47cb14fb1"

[[deps.Artifacts]]
uuid = "56f22d72-fd6d-98f1-02f0-08ddc0907c33"
version = "1.11.0"

[[deps.Base64]]
uuid = "2a0f44e3-6c83-55bd-87e4-b1978d98bd5f"
version = "1.11.0"

[[deps.BitFlags]]
git-tree-sha1 = "0691e34b3bb8be9307330f88d1a3c3f25466c24d"
uuid = "d1d4a3ce-64b1-5f1a-9ba4-7e7e69966f35"
version = "0.1.9"

[[deps.CSV]]
deps = ["CodecZlib", "Dates", "FilePathsBase", "InlineStrings", "Mmap", "Parsers", "PooledArrays", "PrecompileTools", "SentinelArrays", "Tables", "Unicode", "WeakRefStrings", "WorkerUtilities"]
git-tree-sha1 = "deddd8725e5e1cc49ee205a1964256043720a6c3"
uuid = "336ed68f-0bac-5ca0-87d4-7b16caf5d00b"
version = "0.10.15"

[[deps.CodecZlib]]
deps = ["TranscodingStreams", "Zlib_jll"]
git-tree-sha1 = "bce6804e5e6044c6daab27bb533d1295e4a2e759"
uuid = "944b1d66-785c-5afd-91f1-9de20f533193"
version = "0.7.6"

[[deps.Compat]]
deps = ["TOML", "UUIDs"]
git-tree-sha1 = "8ae8d32e09f0dcf42a36b90d4e17f5dd2e4c4215"
uuid = "34da2185-b29b-5c13-b0c7-acf172513d20"
version = "4.16.0"
weakdeps = ["Dates", "LinearAlgebra"]

    [deps.Compat.extensions]
    CompatLinearAlgebraExt = "LinearAlgebra"

[[deps.CompilerSupportLibraries_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "e66e0078-7015-5450-92f7-15fbd957f2ae"
version = "1.1.1+0"

[[deps.ConcurrentUtilities]]
deps = ["Serialization", "Sockets"]
git-tree-sha1 = "f36e5e8fdffcb5646ea5da81495a5a7566005127"
uuid = "f0e56b4a-5159-44fe-b623-3e5288b988bb"
version = "2.4.3"

[[deps.Crayons]]
git-tree-sha1 = "249fe38abf76d48563e2f4556bebd215aa317e15"
uuid = "a8cc5b0e-0ffa-5ad4-8c14-923d3ee1735f"
version = "4.1.1"

[[deps.DataAPI]]
git-tree-sha1 = "abe83f3a2f1b857aac70ef8b269080af17764bbe"
uuid = "9a962f9c-6df0-11e9-0e5d-c546b8b5ee8a"
version = "1.16.0"

[[deps.DataFrames]]
deps = ["Compat", "DataAPI", "DataStructures", "Future", "InlineStrings", "InvertedIndices", "IteratorInterfaceExtensions", "LinearAlgebra", "Markdown", "Missings", "PooledArrays", "PrecompileTools", "PrettyTables", "Printf", "Random", "Reexport", "SentinelArrays", "SortingAlgorithms", "Statistics", "TableTraits", "Tables", "Unicode"]
git-tree-sha1 = "fb61b4812c49343d7ef0b533ba982c46021938a6"
uuid = "a93c6f00-e57d-5684-b7b6-d8193f3e46c0"
version = "1.7.0"

[[deps.DataStructures]]
deps = ["Compat", "InteractiveUtils", "OrderedCollections"]
git-tree-sha1 = "1d0a14036acb104d9e89698bd408f63ab58cdc82"
uuid = "864edb3b-99cc-5e75-8d2d-829cb0a9cfe8"
version = "0.18.20"

[[deps.DataValueInterfaces]]
git-tree-sha1 = "bfc1187b79289637fa0ef6d4436ebdfe6905cbd6"
uuid = "e2d170a0-9d28-54be-80f0-106bbe20a464"
version = "1.0.0"

[[deps.Dates]]
deps = ["Printf"]
uuid = "ade2ca70-3891-5945-98fb-dc099432e06a"
version = "1.11.0"

[[deps.ExceptionUnwrapping]]
deps = ["Test"]
git-tree-sha1 = "d36f682e590a83d63d1c7dbd287573764682d12a"
uuid = "460bff9d-24e4-43bc-9d9f-a8973cb893f4"
version = "0.1.11"

[[deps.FilePathsBase]]
deps = ["Compat", "Dates"]
git-tree-sha1 = "2ec417fc319faa2d768621085cc1feebbdee686b"
uuid = "48062228-2e41-5def-b9a4-89aafe57970f"
version = "0.9.23"
weakdeps = ["Mmap", "Test"]

    [deps.FilePathsBase.extensions]
    FilePathsBaseMmapExt = "Mmap"
    FilePathsBaseTestExt = "Test"

[[deps.Future]]
deps = ["Random"]
uuid = "9fa8497b-333b-5362-9e8d-4d0656e87820"
version = "1.11.0"

[[deps.HTTP]]
deps = ["Base64", "CodecZlib", "ConcurrentUtilities", "Dates", "ExceptionUnwrapping", "Logging", "LoggingExtras", "MbedTLS", "NetworkOptions", "OpenSSL", "PrecompileTools", "Random", "SimpleBufferStream", "Sockets", "URIs", "UUIDs"]
git-tree-sha1 = "c67b33b085f6e2faf8bf79a61962e7339a81129c"
uuid = "cd3eb016-35fb-5094-929b-558a96fad6f3"
version = "1.10.15"

[[deps.InlineStrings]]
git-tree-sha1 = "45521d31238e87ee9f9732561bfee12d4eebd52d"
uuid = "842dd82b-1e85-43dc-bf29-5d0ee9dffc48"
version = "1.4.2"

    [deps.InlineStrings.extensions]
    ArrowTypesExt = "ArrowTypes"
    ParsersExt = "Parsers"

    [deps.InlineStrings.weakdeps]
    ArrowTypes = "31f734f8-188a-4ce0-8406-c8a06bd891cd"
    Parsers = "69de0a69-1ddd-5017-9359-2bf0b02dc9f0"

[[deps.InteractiveUtils]]
deps = ["Markdown"]
uuid = "b77e0a4c-d291-57a0-90e8-8db25a27a240"
version = "1.11.0"

[[deps.InvertedIndices]]
git-tree-sha1 = "0dc7b50b8d436461be01300fd8cd45aa0274b038"
uuid = "41ab1584-1d38-5bbf-9106-f11c6c58b48f"
version = "1.3.0"

[[deps.IteratorInterfaceExtensions]]
git-tree-sha1 = "a3f24677c21f5bbe9d2a714f95dcd58337fb2856"
uuid = "82899510-4779-5014-852e-03e436cf321d"
version = "1.0.0"

[[deps.JLLWrappers]]
deps = ["Artifacts", "Preferences"]
git-tree-sha1 = "a007feb38b422fbdab534406aeca1b86823cb4d6"
uuid = "692b3bcd-3c85-4b1f-b108-f13ce0eb3210"
version = "1.7.0"

[[deps.JSON]]
deps = ["Dates", "Mmap", "Parsers", "Unicode"]
git-tree-sha1 = "31e996f0a15c7b280ba9f76636b3ff9e2ae58c9a"
uuid = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
version = "0.21.4"

[[deps.JSON3]]
deps = ["Dates", "Mmap", "Parsers", "PrecompileTools", "StructTypes", "UUIDs"]
git-tree-sha1 = "eb3edce0ed4fa32f75a0a11217433c31d56bd48b"
uuid = "0f8b85d8-7281-11e9-16c2-39a750bddbf1"
version = "1.14.0"

    [deps.JSON3.extensions]
    JSON3ArrowExt = ["ArrowTypes"]

    [deps.JSON3.weakdeps]
    ArrowTypes = "31f734f8-188a-4ce0-8406-c8a06bd891cd"

[[deps.LaTeXStrings]]
git-tree-sha1 = "dda21b8cbd6a6c40d9d02a73230f9d70fed6918c"
uuid = "b964fa9f-0449-5b57-a5c2-d3ea65f4040f"
version = "1.4.0"

[[deps.Libdl]]
uuid = "8f399da3-3557-5675-b5ff-fb832c97cbdb"
version = "1.11.0"

[[deps.LinearAlgebra]]
deps = ["Libdl", "OpenBLAS_jll", "libblastrampoline_jll"]
uuid = "37e2e46d-f89d-539d-b4ee-838fcccc9c8e"
version = "1.11.0"

[[deps.Logging]]
uuid = "56ddb016-857b-54e1-b83d-db4d58db5568"
version = "1.11.0"

[[deps.LoggingExtras]]
deps = ["Dates", "Logging"]
git-tree-sha1 = "f02b56007b064fbfddb4c9cd60161b6dd0f40df3"
uuid = "e6f89c97-d47a-5376-807f-9c37f3926c36"
version = "1.1.0"

[[deps.Markdown]]
deps = ["Base64"]
uuid = "d6f4376e-aef5-505a-96c1-9c027394607a"
version = "1.11.0"

[[deps.MbedTLS]]
deps = ["Dates", "MbedTLS_jll", "MozillaCACerts_jll", "NetworkOptions", "Random", "Sockets"]
git-tree-sha1 = "c067a280ddc25f196b5e7df3877c6b226d390aaf"
uuid = "739be429-bea8-5141-9913-cc70e7f3736d"
version = "1.1.9"

[[deps.MbedTLS_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "c8ffd9c3-330d-5841-b78e-0817d7145fa1"
version = "2.28.6+0"

[[deps.Missings]]
deps = ["DataAPI"]
git-tree-sha1 = "ec4f7fbeab05d7747bdf98eb74d130a2a2ed298d"
uuid = "e1d29d7a-bbdc-5cf2-9ac0-f12de2c33e28"
version = "1.2.0"

[[deps.Mmap]]
uuid = "a63ad114-7e13-5084-954f-fe012c677804"
version = "1.11.0"

[[deps.MozillaCACerts_jll]]
uuid = "14a3606d-f60d-562e-9121-12d972cd8159"
version = "2023.12.12"

[[deps.NetworkOptions]]
uuid = "ca575930-c2e3-43a9-ace4-1e988b2c1908"
version = "1.2.0"

[[deps.OpenBLAS_jll]]
deps = ["Artifacts", "CompilerSupportLibraries_jll", "Libdl"]
uuid = "4536629a-c528-5b80-bd46-f80d51c5b363"
version = "0.3.27+1"

[[deps.OpenSSL]]
deps = ["BitFlags", "Dates", "MozillaCACerts_jll", "OpenSSL_jll", "Sockets"]
git-tree-sha1 = "38cb508d080d21dc1128f7fb04f20387ed4c0af4"
uuid = "4d8831e6-92b7-49fb-bdf8-b643e874388c"
version = "1.4.3"

[[deps.OpenSSL_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl"]
git-tree-sha1 = "7493f61f55a6cce7325f197443aa80d32554ba10"
uuid = "458c3c95-2e84-50aa-8efc-19380b2a3a95"
version = "3.0.15+3"

[[deps.OrderedCollections]]
git-tree-sha1 = "dfdf5519f235516220579f949664f1bf44e741c5"
uuid = "bac558e1-5e72-5ebc-8fee-abe8a469f55d"
version = "1.6.3"

[[deps.Parsers]]
deps = ["Dates", "PrecompileTools", "UUIDs"]
git-tree-sha1 = "8489905bcdbcfac64d1daa51ca07c0d8f0283821"
uuid = "69de0a69-1ddd-5017-9359-2bf0b02dc9f0"
version = "2.8.1"

[[deps.PooledArrays]]
deps = ["DataAPI", "Future"]
git-tree-sha1 = "36d8b4b899628fb92c2749eb488d884a926614d3"
uuid = "2dfb63ee-cc39-5dd5-95bd-886bf059d720"
version = "1.4.3"

[[deps.PrecompileTools]]
deps = ["Preferences"]
git-tree-sha1 = "5aa36f7049a63a1528fe8f7c3f2113413ffd4e1f"
uuid = "aea7be01-6a6a-4083-8856-8a6e6704d82a"
version = "1.2.1"

[[deps.Preferences]]
deps = ["TOML"]
git-tree-sha1 = "9306f6085165d270f7e3db02af26a400d580f5c6"
uuid = "21216c6a-2e73-6563-6e65-726566657250"
version = "1.4.3"

[[deps.PrettyTables]]
deps = ["Crayons", "LaTeXStrings", "Markdown", "PrecompileTools", "Printf", "Reexport", "StringManipulation", "Tables"]
git-tree-sha1 = "1101cd475833706e4d0e7b122218257178f48f34"
uuid = "08abe8d2-0d0c-5749-adfa-8a2ac140af0d"
version = "2.4.0"

[[deps.Printf]]
deps = ["Unicode"]
uuid = "de0858da-6303-5e67-8744-51eddeeeb8d7"
version = "1.11.0"

[[deps.Random]]
deps = ["SHA"]
uuid = "9a3f8284-a2c9-5f02-9a11-845980a1fd5c"
version = "1.11.0"

[[deps.Reexport]]
git-tree-sha1 = "45e428421666073eab6f2da5c9d310d99bb12f9b"
uuid = "189a3867-3050-52da-a836-e630ba90ab69"
version = "1.2.2"

[[deps.SHA]]
uuid = "ea8e919c-243c-51af-8825-aaa63cd721ce"
version = "0.7.0"

[[deps.SentinelArrays]]
deps = ["Dates", "Random"]
git-tree-sha1 = "d0553ce4031a081cc42387a9b9c8441b7d99f32d"
uuid = "91c51154-3ec4-41a3-a24f-3f23e20d615c"
version = "1.4.7"

[[deps.Serialization]]
uuid = "9e88b42a-f829-5b0c-bbe9-9e923198166b"
version = "1.11.0"

[[deps.SimpleBufferStream]]
git-tree-sha1 = "f305871d2f381d21527c770d4788c06c097c9bc1"
uuid = "777ac1f9-54b0-4bf8-805c-2214025038e7"
version = "1.2.0"

[[deps.Sockets]]
uuid = "6462fe0b-24de-5631-8697-dd941f90decc"
version = "1.11.0"

[[deps.SortingAlgorithms]]
deps = ["DataStructures"]
git-tree-sha1 = "66e0a8e672a0bdfca2c3f5937efb8538b9ddc085"
uuid = "a2af1166-a08f-5f64-846c-94a0d3cef48c"
version = "1.2.1"

[[deps.Statistics]]
deps = ["LinearAlgebra"]
git-tree-sha1 = "ae3bb1eb3bba077cd276bc5cfc337cc65c3075c0"
uuid = "10745b16-79ce-11e8-11f9-7d13ad32a3b2"
version = "1.11.1"

    [deps.Statistics.extensions]
    SparseArraysExt = ["SparseArrays"]

    [deps.Statistics.weakdeps]
    SparseArrays = "2f01184e-e22b-5df5-ae63-d93ebab69eaf"

[[deps.StringManipulation]]
deps = ["PrecompileTools"]
git-tree-sha1 = "a6b1675a536c5ad1a60e5a5153e1fee12eb146e3"
uuid = "892a3eda-7b42-436c-8928-eab12a02cf0e"
version = "0.4.0"

[[deps.StructTypes]]
deps = ["Dates", "UUIDs"]
git-tree-sha1 = "ca4bccb03acf9faaf4137a9abc1881ed1841aa70"
uuid = "856f2bd8-1eba-4b0a-8007-ebc267875bd4"
version = "1.10.0"

[[deps.TOML]]
deps = ["Dates"]
uuid = "fa267f1f-6049-4f14-aa54-33bafae1ed76"
version = "1.0.3"

[[deps.TableTraits]]
deps = ["IteratorInterfaceExtensions"]
git-tree-sha1 = "c06b2f539df1c6efa794486abfb6ed2022561a39"
uuid = "3783bdb8-4a98-5b6b-af9a-565f29a5fe9c"
version = "1.0.1"

[[deps.Tables]]
deps = ["DataAPI", "DataValueInterfaces", "IteratorInterfaceExtensions", "OrderedCollections", "TableTraits"]
git-tree-sha1 = "598cd7c1f68d1e205689b1c2fe65a9f85846f297"
uuid = "bd369af6-aec1-5ad0-b16a-f7cc5008161c"
version = "1.12.0"

[[deps.Test]]
deps = ["InteractiveUtils", "Logging", "Random", "Serialization"]
uuid = "8dfed614-e22c-5e08-85e1-65c5234f0b40"
version = "1.11.0"

[[deps.TranscodingStreams]]
git-tree-sha1 = "0c45878dcfdcfa8480052b6ab162cdd138781742"
uuid = "3bb67fe8-82b1-5028-8e26-92a6c54297fa"
version = "0.11.3"

[[deps.URIs]]
git-tree-sha1 = "67db6cc7b3821e19ebe75791a9dd19c9b1188f2b"
uuid = "5c2747f8-b7ea-4ff2-ba2e-563bfd36b1d4"
version = "1.5.1"

[[deps.UUIDs]]
deps = ["Random", "SHA"]
uuid = "cf7118a7-6976-5b1a-9a39-7adc72f591a4"
version = "1.11.0"

[[deps.Unicode]]
uuid = "4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5"
version = "1.11.0"

[[deps.WeakRefStrings]]
deps = ["DataAPI", "InlineStrings", "Parsers"]
git-tree-sha1 = "b1be2855ed9ed8eac54e5caff2afcdb442d52c23"
uuid = "ea10d353-3f73-51f8-a26c-33c1cb351aa5"
version = "1.4.2"

[[deps.WorkerUtilities]]
git-tree-sha1 = "cd1659ba0d57b71a464a29e64dbc67cfe83d54e7"
uuid = "76eceee3-57b5-4d4a-8e66-0e911cebbf60"
version = "1.6.1"

[[deps.Zlib_jll]]
deps = ["Libdl"]
uuid = "83775a58-1f1d-513f-b197-d71354ab007a"
version = "1.2.13+1"

[[deps.libblastrampoline_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "8e850b90-86db-534c-a0d3-1478176c7d93"
version = "5.11.0+0"
"""

# ╔═╡ Cell order:
# ╠═f87b8466-dc05-11ef-2c7f-6585551df9a1
# ╟─4d81e853-e592-40c0-a66a-f5fa11467fe9
# ╠═15e06b0a-13de-4d70-99aa-f870b3b07732
# ╠═2ffc741b-09c2-4e44-a190-f187a0a7b6cd
# ╟─f56b519f-df0f-442d-835a-e4c8aa94af1f
# ╟─5d72dcbb-c814-4ed5-b9dd-0ba3cdf27b9d
# ╟─0bd70285-6df7-467b-ac34-942d553679dd
# ╠═69290ffd-6841-46f0-b927-6314406e5758
# ╠═f3a15dca-a3be-4a43-976d-e1894ee7e19d
# ╟─91015ec6-05ce-4451-b546-a7da73643dc7
# ╠═137080b5-3c45-4a66-8812-ba52b64bb777
# ╟─3e15aa11-084e-404d-a0c0-4078ef9e5f8b
# ╠═53533056-c888-4e63-8844-24cefdc67007
# ╠═71fbc64b-ca35-4129-a182-95a43deae8db
# ╠═42bc870d-8e98-4d09-b5f8-d3b44e0326b1
# ╠═843b32ef-d77f-483c-b4e6-6e9e5ab78290
# ╟─4a613851-178f-4bd9-8a07-26e9911f49db
# ╟─a64e8d78-ca5e-43e6-bc23-05b074175536
# ╠═df53fd12-1e37-4f3e-9af4-2bddbc6dc477
# ╠═1d9bbec8-3930-484f-9922-10d3f4ce96c0
# ╠═8e99afc7-aa99-4ce5-9d45-a77492f0c412
# ╟─40f83181-b9ff-4cfc-b439-d0027a215cd0
# ╟─cf972491-7e57-4ed1-b04a-87db52568117
# ╟─c433e976-0b1a-4aa7-9b12-52b257a9047d
# ╠═f94c0aca-14f8-480b-864d-bd5a72398a3f
# ╟─22ae387b-abe6-4349-bfcd-97f28bdb00f4
# ╟─b312253b-4322-4f56-96b7-87ef34702ee8
# ╟─65e31759-efb9-426a-b49e-4d8ad4d3a01f
# ╠═f573d1f1-f359-4ef9-8822-337ea58d7938
# ╟─280be0cd-228c-42cb-a65a-1f717c98ceb6
# ╟─4f0aa43d-4e7a-4ea0-82cb-05197cba68bb
# ╠═872d359e-c013-4f72-a569-867d3fa3805d
# ╟─b0070a92-10fc-4610-86eb-a33fa2d9b96a
# ╟─6b605489-2e10-4d80-8160-7913ce8c5661
# ╠═31a396b8-c218-4776-8790-51bf5162f6f1
# ╟─d6453d94-9580-4146-86f9-0511143487a3
# ╠═2fa4826b-8c4a-4c1c-b7d6-571af1753459
# ╟─00000000-0000-0000-0000-000000000001
# ╟─00000000-0000-0000-0000-000000000002
